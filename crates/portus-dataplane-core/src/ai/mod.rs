//! AI gateway: routing LLM requests on fields of their JSON body, and the
//! per-dialect knowledge (usage fields, streaming shapes) the ledger needs.
//! Nothing here touches a socket or a store; the adapters feed body bytes in
//! and act on what comes out.

pub mod budget;
pub mod keys;
pub mod ledger;
pub mod scan;
pub mod usage;
