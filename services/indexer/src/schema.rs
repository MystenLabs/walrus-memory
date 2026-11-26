diesel::table! {
    accounts (account_id) {
        account_id -> Text,
        owner -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    account_owner_deactivations (package_id, account_id) {
        package_id -> Text,
        account_id -> Text,
        owner -> Text,
        account_version -> Int8,
        checkpoint_timestamp_ms -> Int8,
    }
}
