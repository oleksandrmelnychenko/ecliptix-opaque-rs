// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod authentication;

mod registration;

mod state;

pub use authentication::{generate_ke1, generate_ke3, initiator_finish};
pub use registration::{create_registration_request, finalize_registration};
pub use state::{
    InitiatorPhase, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord,
    RegistrationRequest,
};
