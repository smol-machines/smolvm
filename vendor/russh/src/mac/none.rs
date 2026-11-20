use super::{Mac, MacAlgorithm};

pub struct NoMacAlgorithm {}

pub struct NoMac {}

impl MacAlgorithm for NoMacAlgorithm {
    fn key_len(&self) -> usize {
        0
    }

    fn make_mac(&self, _: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(NoMac {})
    }
}

impl Mac for NoMac {
    fn mac_len(&self) -> usize {
        0
    }

    fn compute(&self, _: u32, _: &[u8], _: &mut [u8]) {}
    fn verify(&self, _: u32, _: &[u8], _: &[u8]) -> bool {
        true
    }
}
