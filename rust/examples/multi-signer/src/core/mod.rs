//! Core workflow state and orchestration
//!
//! Shared between GUI and CLI interfaces

pub mod app_state;
pub mod workflow_orchestrator;

pub use app_state::{AppState, WorkflowState};
pub use workflow_orchestrator::WorkflowOrchestrator;
