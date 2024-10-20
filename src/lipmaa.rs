// SPDX-License-Identifier: FSL-1.1
/// Trait for calculating Lipmaa numbers for unsigned integers
pub trait Lipmaa {
    /// Tests if this is a number with a long lipmaa backlink
    fn is_lipmaa(&self) -> bool;
    /// Returns the lipmaa number
    fn lipmaa(&self) -> Self;
    /// Returns the greatest number in this number's certificate set
    fn node_z(&self) -> Self;
}

impl Lipmaa for u64 {
    fn is_lipmaa(&self) -> bool {
        if *self == 0 {
            return false;
        }
        self.lipmaa() + 1 != *self
    }

    fn lipmaa(&self) -> Self {
        if *self == 0 {
            return *self;
        }
        let mut m = 1;
        let mut po3 = 3;
        while m < *self {
            po3 *= 3;
            m = (po3 - 1) / 2;
        }
        po3 /= 3;
        if m != *self {
            let mut x = *self;
            while x != 0 {
                m = (po3 - 1) / 2;
                po3 /= 3;
                x %= m;
            }
            if m != po3 {
                po3 = m;
            }
        }
        *self - po3
    }

    fn node_z(&self) -> Self {
        let mut m = 1;
        let mut po3 = 3;
        while m < *self {
            po3 *= 3;
            m = (po3 - 1) / 2;
        }
        po3 / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_zero() {
        0.is_lipmaa();
    }

    #[test]
    fn lipmaa_one() {
        assert!(!0.is_lipmaa());
    }

    #[test]
    fn lipmaa_four() {
        assert!(4.is_lipmaa());
    }

    #[test]
    fn test_array_tuple() {
        // an array of tuples (index, * is_lipmaa (long hop), backlink index )
        // Sequence number...	...backlinks to sequence number...
        // 1	0
        // 2	1
        // 3	2
        // 4	* 1
        // 5	4
        // 6	5
        // 7	6
        // 8	* 4
        // 9	8
        // 10	9
        // 11	10
        // 12	* 8
        // 13	* 4
        // 14	13
        // 15	14
        // 16	15
        // 17	* 13
        // 18	17
        // 19	18
        // 20	19
        // 21	* 17
        // 22	21
        // 23	22
        // 24	23
        // 25	* 21
        // 26	* 13
        // 27	26
        // 28	27
        // 29	28
        // 30	* 26
        // 31	30
        // 32	31
        // 33	32
        // 34	* 30
        // 35	34
        // 36	35
        // 37	36
        // 38	* 34
        // 39	* 26
        // 40	* 13
        let lipmaabacklinks = [
            (1, false, 0),
            (2, false, 1),
            (3, false, 2),
            (4, true, 1),
            (5, false, 4),
            (6, false, 5),
            (7, false, 6),
            (8, true, 4),
            (9, false, 8),
            (10, false, 9),
            (11, false, 10),
            (12, true, 8),
            (13, true, 4),
            (14, false, 13),
            (15, false, 14),
            (16, false, 15),
            (17, true, 13),
            (18, false, 17),
            (19, false, 18),
            (20, false, 19),
            (21, true, 17),
            (22, false, 21),
            (23, false, 22),
            (24, false, 23),
            (25, true, 21),
            (26, true, 13),
            (27, false, 26),
            (28, false, 27),
            (29, false, 28),
            (30, true, 26),
            (31, false, 30),
            (32, false, 31),
            (33, false, 32),
            (34, true, 30),
            (35, false, 34),
            (36, false, 35),
            (37, false, 36),
            (38, true, 34),
            (39, true, 26),
            (40, true, 13),
        ];

        for (i, is_lipmaa_longhop, backlink) in lipmaabacklinks.iter() {
            assert_eq!(i.lipmaa(), *backlink);
            assert_eq!(i.is_lipmaa(), *is_lipmaa_longhop);
        }
    }
}
