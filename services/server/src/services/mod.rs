//! Service-layer capabilities — callable building blocks that handlers compose.
//!
//! Each service is a trait + a default production implementation. Handlers
//! receive trait objects (`Arc<dyn Embedder>`, `Arc<dyn Extractor>`) via
//! `AppState`, so alternative implementations (mock, local model, hybrid)
//! can be swapped in at startup without touching handler code.
//!
//! Why "services" and not "pipeline": Walrus Memory isn't a single linear flow.
//! `analyze` extracts facts then embeds+stores each; `remember` summarises
//! long text then embeds; `recall` embeds the query then hydrates hits;
//! `ask` recalls then asks an LLM. Different handlers compose these
//! capabilities in different orders, with different fan-out and parallelism.
//! Each module here is a *callable capability*, not a "stage" data flows
//! through. See `whole-system-documents/memory-protocol-improvement/refactor-plan/PLAN.md`.
//!
//! Scope boundary (Phase 2): this module owns *text-in, vector/facts-out*
//! — embedding and LLM-driven fact extraction. It does NOT own:
//! - persistence — that's [`crate::engine`].
//! - the `/api/remember` long-text summarisation path (`summarize_*` in
//!   `routes.rs`) — it shares [`llm_chat`] types but stays in the handler
//!   for now; it's tangled with the embed-prep fan-out.
//! - composite scoring / re-ranking / consolidation — the [`ranker`] and
//!   [`consolidator`] modules are reserved namespace, doc-only until a
//!   real caller exists (the AI-improvement track).

pub mod email;
pub(crate) mod embedder;
pub mod extractor;
pub mod llm_chat;
pub mod ranker;

// Placeholder module — reserved namespace for the consolidator
// (linked-memory-ids + supersede logic). Doc-only until a real caller
// exists; inventing a trait without one would be premature design.
pub mod consolidator;

pub use embedder::{Embedder, OpenAiEmbedder};
pub use extractor::{Extractor, LlmExtractor};
pub use ranker::{CompositeRanker, Ranker};
