// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use super::LeaseId;
use crate::http::headers;

#[derive(Debug, Clone, Copy)]
pub struct ProposedLeaseId(LeaseId);

impl From<LeaseId> for ProposedLeaseId {
    fn from(lease_id: LeaseId) -> Self {
        Self(lease_id)
    }
}

impl headers::Header for ProposedLeaseId {
    fn name(&self) -> headers::HeaderName {
        headers::PROPOSED_LEASE_ID
    }

    fn value(&self) -> headers::HeaderValue {
        format!("{}", self.0).into()
    }
}
