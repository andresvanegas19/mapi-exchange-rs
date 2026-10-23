// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use outlook_mapi_http::props::tags as p;

/// Standard MAPI property tags (MS-OXPROPS) shown by name in restriction trees.
mod t {
    pub const PR_IMPORTANCE: u32 = 0x0017_0003;
    pub const PR_MESSAGE_CLASS_W: u32 = 0x001A_001F;
    pub const PR_SUBJECT_W: u32 = 0x0037_001F;
    pub const PR_MESSAGE_TO_ME: u32 = 0x0057_000B;
    pub const PR_MESSAGE_CC_ME: u32 = 0x0058_000B;
    pub const PR_SENDER_NAME_W: u32 = 0x0C1A_001F;
    pub const PR_SENDER_EMAIL_ADDRESS_W: u32 = 0x0C1F_001F;
    pub const PR_DISPLAY_CC_W: u32 = 0x0E03_001F;
    pub const PR_DISPLAY_TO_W: u32 = 0x0E04_001F;
    pub const PR_MESSAGE_DELIVERY_TIME: u32 = 0x0E06_0040;
    pub const PR_MESSAGE_FLAGS: u32 = 0x0E07_0003;
    pub const PR_MESSAGE_SIZE: u32 = 0x0E08_0003;
    pub const PR_HASATTACH: u32 = 0x0E1B_000B;
    pub const PR_BODY_W: u32 = 0x1000_001F;
    pub const PR_FLAG_STATUS: u32 = 0x1090_0003;
    pub const PR_EMAIL_ADDRESS_W: u32 = 0x3003_001F;
    pub const PR_SMTP_ADDRESS_W: u32 = 0x39FE_001F;
    pub const PR_SENDER_SMTP_ADDRESS_W: u32 = 0x5D01_001F;
}

pub fn name(tag: u32) -> String {
    let name = match tag {
        t::PR_IMPORTANCE => "PR_IMPORTANCE",
        t::PR_MESSAGE_CLASS_W => "PR_MESSAGE_CLASS_W",
        t::PR_SUBJECT_W => "PR_SUBJECT_W",
        t::PR_MESSAGE_TO_ME => "PR_MESSAGE_TO_ME",
        t::PR_MESSAGE_CC_ME => "PR_MESSAGE_CC_ME",
        t::PR_SENDER_NAME_W => "PR_SENDER_NAME_W",
        t::PR_SENDER_EMAIL_ADDRESS_W => "PR_SENDER_EMAIL_ADDRESS_W",
        t::PR_DISPLAY_CC_W => "PR_DISPLAY_CC_W",
        t::PR_DISPLAY_TO_W => "PR_DISPLAY_TO_W",
        t::PR_MESSAGE_DELIVERY_TIME => "PR_MESSAGE_DELIVERY_TIME",
        t::PR_MESSAGE_FLAGS => "PR_MESSAGE_FLAGS",
        t::PR_MESSAGE_SIZE => "PR_MESSAGE_SIZE",
        t::PR_HASATTACH => "PR_HASATTACH",
        t::PR_BODY_W => "PR_BODY_W",
        t::PR_FLAG_STATUS => "PR_FLAG_STATUS",
        t::PR_EMAIL_ADDRESS_W => "PR_EMAIL_ADDRESS_W",
        t::PR_SMTP_ADDRESS_W => "PR_SMTP_ADDRESS_W",
        t::PR_SENDER_SMTP_ADDRESS_W => "PR_SENDER_SMTP_ADDRESS_W",
        p::PR_DISPLAY_NAME_W => "PR_DISPLAY_NAME_W",
        p::PR_FOLDER_ID => "PR_FOLDER_ID",
        p::PR_MID => "PR_MID",
        p::PR_ENTRYID => "PR_ENTRYID",
        p::PR_FOLDER_TYPE => "PR_FOLDER_TYPE",
        p::PR_CONTENT_COUNT => "PR_CONTENT_COUNT",
        p::PR_CONTAINER_CLASS_W => "PR_CONTAINER_CLASS_W",
        p::PR_LAST_MODIFICATION_TIME => "PR_LAST_MODIFICATION_TIME",
        p::PR_WB_SF_TEMPLATE_ID => "PR_WB_SF_TEMPLATE_ID",
        p::PR_WB_SF_ID => "PR_WB_SF_ID",
        p::PR_WB_SF_DEFINITION => "PR_WB_SF_DEFINITION",
        p::PR_WB_SF_RECREATE_INFO => "PR_WB_SF_RECREATE_INFO",
        p::PR_WB_SF_STORAGE_TYPE => "PR_WB_SF_STORAGE_TYPE",
        p::PR_WB_SF_TAG => "PR_WB_SF_TAG",
        p::PR_WB_SF_EFP_FLAGS => "PR_WB_SF_EFP_FLAGS",
        p::PR_WB_SF_LAST_USED => "PR_WB_SF_LAST_USED",
        p::PR_WB_SF_EXPIRATION => "PR_WB_SF_EXPIRATION",
        _ => return format!("0x{tag:08x}"),
    };
    format!("{name} (0x{tag:08x})")
}
