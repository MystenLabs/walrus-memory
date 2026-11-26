use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use diesel::{prelude::*, upsert::excluded};
use diesel_async::RunQueryDsl;
use move_core_types::account_address::AccountAddress;
use serde::Deserialize;
use sui_indexer_alt_framework::{
    pipeline::Processor,
    postgres::{handler::Handler, Connection},
    types::{
        base_types::ObjectID,
        effects::TransactionEffectsAPI,
        full_checkpoint_content::Checkpoint,
        transaction::{Argument, CallArg, Command, TransactionDataAPI, TransactionKind},
    },
    FieldCount,
};

use crate::schema::account_owner_deactivations as table;

#[derive(Deserialize)]
struct Deactivation {
    account_id: [u8; 32],
    owner: [u8; 32],
}

#[derive(Clone, FieldCount, Insertable)]
#[diesel(table_name = table)]
pub struct OwnerDeactivation {
    package_id: String,
    account_id: String,
    owner: String,
    account_version: i64,
    checkpoint_timestamp_ms: i64,
}

pub struct OwnerDeactivationPipeline {
    pub package: AccountAddress,
}

#[async_trait]
impl Processor for OwnerDeactivationPipeline {
    const NAME: &'static str = "account_owner_deactivations_v1";
    type Value = OwnerDeactivation;

    async fn process(&self, checkpoint: &Arc<Checkpoint>) -> anyhow::Result<Vec<Self::Value>> {
        let mut rows = Vec::new();
        for tx in &checkpoint.transactions {
            if !tx.effects.status().is_ok() {
                continue;
            }
            let data = &tx.transaction;
            let TransactionKind::ProgrammableTransaction(pt) = data.kind() else {
                continue;
            };
            for event in tx.events.iter().flat_map(|events| &events.data) {
                if event.type_.address != self.package
                    || event.type_.module.as_str() != "account"
                    || event.type_.name.as_str() != "AccountDeactivated"
                {
                    continue;
                }
                let event_data: Deactivation = bcs::from_bytes(&event.contents)?;
                if data.sender().as_ref() != event_data.owner
                    || event.sender != data.sender()
                    || event.transaction_module.as_str() != "account"
                    || !calls_owner_deactivation(
                        &pt.inputs,
                        &pt.commands,
                        event.package_id,
                        &event_data.account_id,
                    )
                {
                    continue;
                }
                let account_version = tx
                    .output_objects(&checkpoint.object_set)
                    .find(|object| object.id().as_ref() == event_data.account_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!("deactivation account is missing from checkpoint outputs")
                    })?
                    .version()
                    .value();
                rows.push(OwnerDeactivation {
                    package_id: format!("0x{}", self.package.to_hex()),
                    account_id: format!("0x{}", hex::encode(event_data.account_id)),
                    owner: format!("0x{}", hex::encode(event_data.owner)),
                    account_version: account_version.try_into()?,
                    checkpoint_timestamp_ms: checkpoint.summary.timestamp_ms.try_into()?,
                });
            }
        }
        Ok(rows)
    }
}

fn calls_owner_deactivation(
    inputs: &[CallArg],
    commands: &[Command],
    pkg: ObjectID,
    account_id: &[u8; 32],
) -> bool {
    // The admin freeze emits the same event. Even a transaction signed by the
    // account owner must call the owner entrypoint on the event's exact account.
    commands.iter().any(|command| {
        let Command::MoveCall(call) = command else { return false; };
        if call.package != pkg || call.module != "account" || call.function != "deactivate_account" {
            return false;
        }
        let Some(Argument::Input(index)) = call.arguments.as_slice().first() else { return false; };
        matches!(inputs.get(usize::from(*index)), Some(CallArg::Object(object)) if object.id().as_ref() == account_id)
    })
}

#[async_trait]
impl Handler for OwnerDeactivationPipeline {
    async fn commit<'a>(
        values: &[Self::Value],
        conn: &mut Connection<'a>,
    ) -> anyhow::Result<usize> {
        // PostgreSQL requires one row per conflict key in each insert. Ordered
        // keys also keep lock acquisition consistent across concurrent batches.
        let mut latest = BTreeMap::new();
        for value in values {
            let current = latest
                .entry((&value.package_id, &value.account_id))
                .or_insert(value);
            if current.account_version < value.account_version {
                *current = value;
            }
        }
        let rows: Vec<_> = latest.into_values().collect();
        let updated = diesel::insert_into(table::table)
            .values(rows)
            .on_conflict((table::package_id, table::account_id))
            .do_update()
            .set((
                table::owner.eq(excluded(table::owner)),
                table::account_version.eq(excluded(table::account_version)),
                table::checkpoint_timestamp_ms.eq(excluded(table::checkpoint_timestamp_ms)),
            ))
            .execute(conn)
            .await?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use sui_indexer_alt_framework::types::transaction::{ObjectArg, ProgrammableMoveCall};

    use super::*;

    #[test]
    fn requires_owner_entrypoint_on_the_exact_account_and_package() {
        let owner_account = ObjectID::from_hex_literal("0x1").unwrap();
        let other_account = ObjectID::from_hex_literal("0x2").unwrap();
        let package = ObjectID::from_hex_literal("0x3").unwrap();
        let inputs = [owner_account, other_account].map(|id| {
            CallArg::Object(ObjectArg::SharedObject {
                id,
                initial_shared_version: 1.into(),
                mutability:
                    sui_indexer_alt_framework::types::transaction::SharedObjectMutability::Mutable,
            })
        });
        let call = |function: &str, input| {
            Command::MoveCall(Box::new(ProgrammableMoveCall {
                package,
                module: "account".into(),
                function: function.into(),
                type_arguments: vec![],
                arguments: vec![Argument::Input(input)],
            }))
        };
        let id = owner_account.into_bytes();
        assert!(!calls_owner_deactivation(
            &inputs,
            &[call("admin_deactivate_account", 0)],
            package,
            &id
        ));
        assert!(!calls_owner_deactivation(
            &inputs,
            &[
                call("deactivate_account", 1),
                call("admin_deactivate_account", 0)
            ],
            package,
            &id
        ));
        assert!(calls_owner_deactivation(
            &inputs,
            &[
                call("deactivate_account", 0),
                call("admin_deactivate_account", 0)
            ],
            package,
            &id
        ));
        assert!(!calls_owner_deactivation(
            &inputs,
            &[call("deactivate_account", 0)],
            other_account,
            &id
        ));
    }
}
