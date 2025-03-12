// Copyright (c) Microsoft Corporation. All rights reserved.
//
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) Rust Code Generator. DO NOT EDIT.

// BEGIN GENERATED CODE -- do not edit from here till END
mod generated;

pub mod clients {
    mod blob_client;
    mod blob_container_client;
    mod blob_service_client;

    pub use blob_client::BlobClient;
    pub use blob_container_client::BlobContainerClient as ContainerClient;
    pub use blob_service_client::BlobServiceClient as ServiceClient;

    pub use crate::generated::clients::{
        BlobAppendBlobClient, BlobBlobClient, BlobBlockBlobClient,
        BlobClient as GeneratedBlobClient, BlobClientOptions, BlobContainerClient,
        BlobPageBlobClient, BlobServiceClient,
    };
}

pub mod models {
    pub use crate::generated::clients::method_options::{
        BlobAppendBlobClientAppendBlockFromUrlOptions, BlobAppendBlobClientAppendBlockOptions,
        BlobAppendBlobClientCreateOptions, BlobAppendBlobClientSealOptions,
        BlobBlobClientAbortCopyFromUrlOptions, BlobBlobClientAcquireLeaseOptions,
        BlobBlobClientBreakLeaseOptions, BlobBlobClientChangeLeaseOptions,
        BlobBlobClientCopyFromUrlOptions, BlobBlobClientCreateSnapshotOptions,
        BlobBlobClientDeleteImmutabilityPolicyOptions, BlobBlobClientDeleteOptions,
        BlobBlobClientDownloadOptions, BlobBlobClientGetAccountInfoOptions,
        BlobBlobClientGetPropertiesOptions, BlobBlobClientGetTagsOptions,
        BlobBlobClientQueryOptions, BlobBlobClientReleaseLeaseOptions,
        BlobBlobClientRenewLeaseOptions, BlobBlobClientSetExpiryOptions,
        BlobBlobClientSetHttpHeadersOptions, BlobBlobClientSetImmutabilityPolicyOptions,
        BlobBlobClientSetLegalHoldOptions, BlobBlobClientSetMetadataOptions,
        BlobBlobClientSetTagsOptions, BlobBlobClientSetTierOptions,
        BlobBlobClientStartCopyFromUrlOptions, BlobBlobClientUndeleteOptions,
        BlobBlockBlobClientCommitBlockListOptions, BlobBlockBlobClientGetBlockListOptions,
        BlobBlockBlobClientPutBlobFromUrlOptions, BlobBlockBlobClientStageBlockFromUrlOptions,
        BlobBlockBlobClientStageBlockOptions, BlobBlockBlobClientUploadOptions,
        BlobContainerClientAcquireLeaseOptions, BlobContainerClientBreakLeaseOptions,
        BlobContainerClientChangeLeaseOptions, BlobContainerClientCreateOptions,
        BlobContainerClientDeleteOptions, BlobContainerClientFilterBlobsOptions,
        BlobContainerClientGetAccessPolicyOptions, BlobContainerClientGetAccountInfoOptions,
        BlobContainerClientGetPropertiesOptions, BlobContainerClientReleaseLeaseOptions,
        BlobContainerClientRenameOptions, BlobContainerClientRenewLeaseOptions,
        BlobContainerClientRestoreOptions, BlobContainerClientSetAccessPolicyOptions,
        BlobContainerClientSetMetadataOptions, BlobContainerClientSubmitBatchOptions,
        BlobPageBlobClientClearPagesOptions, BlobPageBlobClientCopyIncrementalOptions,
        BlobPageBlobClientCreateOptions, BlobPageBlobClientResizeOptions,
        BlobPageBlobClientUpdateSequenceNumberOptions, BlobPageBlobClientUploadPagesFromUrlOptions,
        BlobPageBlobClientUploadPagesOptions, BlobServiceClientFilterBlobsOptions,
        BlobServiceClientGetAccountInfoOptions, BlobServiceClientGetPropertiesOptions,
        BlobServiceClientGetStatisticsOptions, BlobServiceClientGetUserDelegationKeyOptions,
        BlobServiceClientSetPropertiesOptions, BlobServiceClientSubmitBatchOptions,
    };
    pub use crate::generated::enums::*;
    pub use crate::generated::models::*;

    mod blob_properties;
    pub use blob_properties::BlobProperties;

    mod container_properties;
    pub use container_properties::ContainerProperties;
}

pub use crate::generated::clients::{BlobClient, BlobClientOptions};
// END GENERATED CODE

pub(crate) mod pipeline;
