// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![forbid(unsafe_code)]

mod authentication;

mod registration;

mod state;

pub use authentication::{generate_ke2, responder_finish};
pub use opaque_core::oprf::{InMemoryEvaluator, OprfEvaluator};
pub use registration::{build_credentials, create_registration_response};
pub use state::{
    Ke2Message, OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderKeyPair,
    ResponderPhase, ResponderState,
};
