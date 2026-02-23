//! XMSS address scheme (RFC 8391 Section 2.5).
//!
//! 32-byte address structure (always uncompressed):
//!   [0:4]   layer address
//!   [4:12]  tree address (8 bytes)
//!   [12:16] type (0=OTS, 1=L-tree, 2=HashTree)
//!   [16:20] OTS addr / L-tree addr / padding
//!   [20:24] chain addr / tree height
//!   [24:28] hash addr / tree index
//!   [28:32] key-and-mask (0=key, 1/2=bitmask)

#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum XmssAdrsType {
    Ots = 0,
    LTree = 1,
    HashTree = 2,
}

#[derive(Clone)]
pub(crate) struct XmssAdrs {
    bytes: [u8; 32],
}

impl XmssAdrs {
    pub fn new() -> Self {
        Self { bytes: [0u8; 32] }
    }

    pub fn set_layer_addr(&mut self, layer: u32) {
        self.bytes[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    pub fn set_tree_addr(&mut self, tree: u64) {
        self.bytes[4..12].copy_from_slice(&tree.to_be_bytes());
    }

    pub fn set_type(&mut self, addr_type: XmssAdrsType) {
        self.bytes[12..16].copy_from_slice(&(addr_type as u32).to_be_bytes());
        // Zero remaining fields when changing type
        self.bytes[16..32].fill(0);
    }

    pub fn set_ots_addr(&mut self, ots: u32) {
        self.bytes[16..20].copy_from_slice(&ots.to_be_bytes());
    }

    pub fn set_ltree_addr(&mut self, ltree: u32) {
        self.bytes[16..20].copy_from_slice(&ltree.to_be_bytes());
    }

    pub fn set_chain_addr(&mut self, chain: u32) {
        self.bytes[20..24].copy_from_slice(&chain.to_be_bytes());
    }

    pub fn set_hash_addr(&mut self, hash: u32) {
        self.bytes[24..28].copy_from_slice(&hash.to_be_bytes());
    }

    pub fn set_tree_height(&mut self, height: u32) {
        self.bytes[20..24].copy_from_slice(&height.to_be_bytes());
    }

    pub fn set_tree_index(&mut self, index: u32) {
        self.bytes[24..28].copy_from_slice(&index.to_be_bytes());
    }

    pub fn set_key_and_mask(&mut self, km: u32) {
        self.bytes[28..32].copy_from_slice(&km.to_be_bytes());
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmss_adrs_set_get() {
        let mut adrs = XmssAdrs::new();
        adrs.set_layer_addr(3);
        adrs.set_tree_addr(0xABCD);
        adrs.set_type(XmssAdrsType::Ots);
        adrs.set_ots_addr(7);
        adrs.set_chain_addr(15);
        adrs.set_hash_addr(9);
        adrs.set_key_and_mask(1);

        let b = adrs.as_bytes();
        assert_eq!(&b[0..4], &3u32.to_be_bytes());
        assert_eq!(&b[4..12], &0xABCDu64.to_be_bytes());
        assert_eq!(&b[12..16], &0u32.to_be_bytes()); // Ots=0
        assert_eq!(&b[16..20], &7u32.to_be_bytes());
        assert_eq!(&b[20..24], &15u32.to_be_bytes());
        assert_eq!(&b[24..28], &9u32.to_be_bytes());
        assert_eq!(&b[28..32], &1u32.to_be_bytes());
    }

    #[test]
    fn test_xmss_adrs_set_type_clears_trailing() {
        let mut adrs = XmssAdrs::new();
        adrs.set_type(XmssAdrsType::Ots);
        adrs.set_ots_addr(99);
        adrs.set_chain_addr(55);
        adrs.set_hash_addr(77);
        adrs.set_key_and_mask(2);

        // Verify fields are set
        assert_ne!(&adrs.as_bytes()[16..32], &[0u8; 16]);

        // set_type should zero bytes [16:32]
        adrs.set_type(XmssAdrsType::HashTree);
        assert_eq!(&adrs.as_bytes()[16..32], &[0u8; 16]);
        // Type field should be HashTree=2
        assert_eq!(&adrs.as_bytes()[12..16], &2u32.to_be_bytes());
    }
}
