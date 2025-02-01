//! Core Paillier encryption scheme supporting ciphertext addition and plaintext multiplication.

use std::borrow::{Borrow, Cow};
use std::ops::Neg;
use std::time::Instant;

use rayon::join;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{traits::*, JoyeLibert};
use crate::{
    BigInt, DecryptionKey, EncryptionKey, Keypair,
    Paillier, RawCiphertext, RawPlaintext,
};
use curv::arithmetic::traits::*;

#[cfg(not(test))] 
pub use log::{info, warn}; // Use log crate when building application

#[cfg(test)]
use std::{println as info, println as warn};



impl Keypair {
    /// Generate default encryption and decryption keys.
    pub fn keys(&self) -> (EncryptionKey, DecryptionKey) {
        (EncryptionKey::from(self), DecryptionKey::from(self))
    }
}

impl<'p, 'q, 'y, 'k> From<(&'p BigInt, &'q BigInt, &'y BigInt, &'k usize)> for Keypair {
    fn from((p, q, y, k): (&'p BigInt, &'q BigInt, &'y BigInt, &'k usize)) -> Keypair {
        Keypair {
            p: p.clone(),
            q: q.clone(),
            y: y.clone(),
            k: k.clone(),
        }
    }
}

impl<'kp> From<&'kp Keypair> for EncryptionKey {
    fn from(keypair: &'kp Keypair) -> Self {
        
        EncryptionKey{
            n: keypair.p.clone() * keypair.q.clone(),
            y: keypair.y.clone(),
            k: keypair.k
        }
    }
}

impl Serialize for EncryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(EncryptionKey::deserialize(deserializer)?)
    }
}

impl<'kp> From<&'kp Keypair> for DecryptionKey {
    fn from(keypair: &'kp Keypair) -> DecryptionKey {
        DecryptionKey {
            p: keypair.p.clone(),
            q: keypair.q.clone(),
            y: keypair.y.clone(),
            k: keypair.k,
        }
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(DecryptionKey::deserialize(deserializer)?)
    }
}

#[derive(Debug, PartialEq)]
pub struct Randomness(pub BigInt);

#[derive(Debug, PartialEq)]
pub struct PrecomputedRandomness(BigInt);

impl Randomness {
    pub fn sample(ek: &EncryptionKey) -> Randomness {
        Randomness(BigInt::sample_below(&ek.n))
    }
}

impl From<BigInt> for Randomness {
    fn from(x: BigInt) -> Randomness {
        Randomness(x)
    }
}

impl<'b> From<&'b BigInt> for Randomness {
    fn from(x: &'b BigInt) -> Randomness {
        Randomness(x.clone())
    }
}

impl<'b> From<BigInt> for RawPlaintext<'b> {
    fn from(x: BigInt) -> Self {
        RawPlaintext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawPlaintext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawPlaintext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawPlaintext<'b>> for BigInt {
    fn from(x: RawPlaintext<'b>) -> Self {
        x.0.into_owned()
    }
}

impl<'b> From<BigInt> for RawCiphertext<'b> {
    fn from(x: BigInt) -> Self {
        RawCiphertext(Cow::Owned(x))
    }
}

impl<'b> From<&'b BigInt> for RawCiphertext<'b> {
    fn from(x: &'b BigInt) -> Self {
        RawCiphertext(Cow::Borrowed(x))
    }
}

impl<'b> From<RawCiphertext<'b>> for BigInt {
    fn from(x: RawCiphertext<'b>) -> Self {
        x.0.into_owned()
    }
}
/// ///////////////////////////////////////////
/// encryption  part
/// ///////////////////////////////////////////
impl<'m, 'd> Encrypt<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'d>> for JoyeLibert {
    fn encrypt(ek: &EncryptionKey, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let mut x = Randomness::sample(ek);
        // Pick a random x in Z_N^*
        while  x.0.cmp(&BigInt::zero()).is_eq() {
            x = Randomness::sample(ek);
        }
        // info!("x: {:?}", x);

    
        // Compute 2^msgsize
        let mut k_exp = BigInt::new();
        k_exp = BigInt::ui_pow_ui(2, ek.k as u32);
        // info!("k_exp: {:?}", k_exp);
    
        // let mut tmp1 = BigInt::new();
        let mut tmp2 = BigInt::new();
    
        // tmp1 = ek.y.pow()

        let mut tmp1 = BigInt::mod_pow(&ek.y, &m.0.borrow(), &ek.n);
        let mut tmp2 = BigInt::mod_pow(&x.0, &k_exp, &ek.n);
        // info!("tmp1: {:?}", tmp1);
        // info!("tmp2: {:?}", tmp2);
    
    
        // info!("c: {:?}", *c);
        let c = tmp1 * tmp2 % ek.n.borrow();
        // *c = tmp1.borrow() * tmp2.borrow();
        // // info!("c: {:?}", *c);
        // *c = c.borrow() % N;
        // // info!("c: {:?}", *c);


        // let r = Randomness::sample(ek);
        // let rn = BigInt::mod_pow(&r.0, &ek.n, &ek.nn);
        // let gm: BigInt = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.nn;
        // let c = (gm * rn) % &ek.nn;
        info!("enc result: {:?}", c);
        RawCiphertext(Cow::Owned(c))
    }
}



impl<'c, 'm> Decrypt<DecryptionKey, RawCiphertext<'c>, RawPlaintext<'m>> for JoyeLibert {
    fn decrypt(dk: &DecryptionKey, c: RawCiphertext<'c>) -> RawPlaintext<'m> {
        Self::decrypt(dk, &c)
    }
}

/// ///////////////////////////////////////////
/// TODO
/// ///////////////////////////////////////////
impl<'c, 'm> Decrypt<DecryptionKey, &'c RawCiphertext<'c>, RawPlaintext<'m>> for JoyeLibert {
    fn decrypt(dk: &DecryptionKey, c: &'c RawCiphertext<'c>) -> RawPlaintext<'m> {
        let mut m = BigInt::zero();
        let mut C = BigInt::mod_pow(
            c.0.borrow(),
            &((&dk.p - &BigInt::one()) / BigInt::ui_pow_ui(2, dk.k as u32)),
            &dk.p
        );
        let mut D = BigInt::mod_inv(
            &BigInt::mod_pow(
                &dk.y,
                &((&dk.p - &BigInt::one()) / BigInt::ui_pow_ui(2, dk.k as u32)),
                &dk.p
            ),
            &dk.p
        ).expect("D must have an inverse modulo p");

        for i in 0..dk.k {
            let z = BigInt::mod_pow(
                &C,
                &BigInt::ui_pow_ui(2, dk.k as u32 - i as u32 - 1),
                &dk.p
            );

            if z != BigInt::one() {
                m += BigInt::ui_pow_ui(2, i as u32);
                C = (C * &D) % &dk.p;
            }

            if i < dk.k - 2 {
                D = (&D * &D) % &dk.p;
            }
        }

        RawPlaintext(Cow::Owned(m))
    }
}



impl<'c1, 'c2, 'd> Add<EncryptionKey, RawCiphertext<'c1>, RawCiphertext<'c2>, RawCiphertext<'d>>
    for JoyeLibert
{
    fn add(
        ek: &EncryptionKey,
        c1: RawCiphertext<'c1>,
        c2: RawCiphertext<'c2>,
    ) -> RawCiphertext<'d> {
        let d = (c1.0.borrow() as &BigInt * c2.0.borrow() as &BigInt) % &ek.n;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for JoyeLibert
{
    fn add(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        let c1 = c.0.borrow() as &BigInt;
        let c2 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.n;
        let d = (c1 * c2) % &ek.n;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Add<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for JoyeLibert
{
    fn add(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        let c1 = (m.0.borrow() as &BigInt * &ek.n + 1) % &ek.n;
        let c2 = c.0.borrow() as &BigInt;
        let d = (c1 * c2) % &ek.n;
        RawCiphertext(Cow::Owned(d))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawCiphertext<'c>, RawPlaintext<'m>, RawCiphertext<'d>>
    for JoyeLibert
{
    fn mul(ek: &EncryptionKey, c: RawCiphertext<'c>, m: RawPlaintext<'m>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.n,
        )))
    }
}

impl<'c, 'm, 'd> Mul<EncryptionKey, RawPlaintext<'m>, RawCiphertext<'c>, RawCiphertext<'d>>
    for JoyeLibert
{
    fn mul(ek: &EncryptionKey, m: RawPlaintext<'m>, c: RawCiphertext<'c>) -> RawCiphertext<'d> {
        RawCiphertext(Cow::Owned(BigInt::mod_pow(
            c.0.borrow(),
            m.0.borrow(),
            &ek.n,
        )))
    }
}

fn h(p: &BigInt, pp: &BigInt, n: &BigInt) -> BigInt {
    // here we assume:
    //  - p \in {P, Q}
    //  - n = P * Q
    //  - g = 1 + n

    // compute g^{p-1} mod p^2
    let gp = (1 - n) % pp;
    // compute L_p(.)
    let lp = l(&gp, p);
    // compute L_p(.)^{-1}
    BigInt::mod_inv(&lp, p).unwrap()
}

fn l(u: &BigInt, n: &BigInt) -> BigInt {
    (u - 1) / n
}

fn crt_decompose<X, M1, M2>(x: X, m1: M1, m2: M2) -> (BigInt, BigInt)
where
    X: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
{
    (x.borrow() % m1.borrow(), x.borrow() % m2.borrow())
}

fn crt_recombine<X1, X2, M1, M2, I>(x1: X1, x2: X2, m1: M1, m2: M2, m1inv: I) -> BigInt
where
    X1: Borrow<BigInt>,
    X2: Borrow<BigInt>,
    M1: Borrow<BigInt>,
    M2: Borrow<BigInt>,
    I: Borrow<BigInt>,
{
    let diff = BigInt::mod_sub(x2.borrow(), x1.borrow(), m2.borrow());
    //  let mut diff = (x2.borrow() - x1.borrow()) % m2.borrow();
    //  if NumberTests::is_negative(&diff) {
    //      diff += m2.borrow();
    //  }
    let u = (diff * m1inv.borrow()) % m2.borrow();
    x1.borrow() + (u * m1.borrow())
}

/// Extract randomness component of a zero ciphertext.
pub fn extract_nroot(dk: &DecryptionKey, z: &BigInt) -> BigInt {
    let dk_n = &dk.p * &dk.q;

    let dk_pinv = BigInt::mod_inv(&dk.p, &dk.q).unwrap();
    let dk_qminusone = &dk.q - BigInt::one();
    let dk_pminusone = &dk.p - BigInt::one();

    let dk_phi = &dk_pminusone * &dk_qminusone;
    let dk_dn = BigInt::mod_inv(&dk_n, &dk_phi).unwrap();
    let (dk_dp, dk_dq) = crt_decompose(dk_dn, &dk_pminusone, &dk_qminusone);
    let (zp, zq) = crt_decompose(z, &dk.p, &dk.q);

    let rp = BigInt::mod_pow(&zp, &dk_dp, &dk.p);
    let rq = BigInt::mod_pow(&zq, &dk_dq, &dk.q);

    crt_recombine(rp, rq, &dk.p, &dk.q, &dk_pinv)
}

#[cfg(test)]
mod tests {

    use super::*;

    extern crate serde_json;

    fn test_keypair() -> Keypair {
        let p = BigInt::from_str_radix("23199984147340072077100877459017656936448219567273597918425377084508446498270077218316962796544166478076210644017481772229557674431961688814711491654034029474118962639380850425232269199762616300021497775447794820142229798877842201601181840159826692752275435332244961514191205932947191402059591636647466234680633699017671231122769517028405954318320520456512781981317481035207379416665351529504236468027268894334147592929459115692262980255967766460068099605935627696112788016983965697", 10).unwrap();
        let q = BigInt::from_str_radix("4120196551177181142320555358917013281978183440358644160962397416416651419832573597651802801626242982423889846226683075379947282629863952560097870868680519579633891708511743296095770310867584685074913216326441053246896857391796037932887524417348974952536315601038169386121392155952843813596136140931593728122169008557865411183438662740600610069316566164236323384590482864178595944057841296583144489527521836044888912356223978940167746163804598814936249956741645491488661083006092307", 10).unwrap();
        let y = BigInt::from_str_radix("62548236153162950920582674737354856125439401858536935144385993478413061121486980371928408128209882727400293417959163082927415186888758310853816398831608482615345358975922467320556759444327513855593968613290017810053873366431258522855175243977374138436538990932555457606692230904915657171120797095126846155240505784375721569057128071474458405434780305067205040970882897399363200676184249878843504717776101869955609218891065429003101919971540439099207159936288599988795066079552052205818092614899690358914284693646340847623105127868901377713630145449607939585652567911216294062409282783090098974624456450051476806945189886625063362488479433666652202473958746419152615374147650173740236169278951234633260109290538344784317270298764319652826843538369261172043757506922729020811433084597410979510743184933307191523299710824200421324858547697042175955139031354558155351464789556170881576555282202001716821184261307210544672041258818560179654243220444457158628485842317", 16).unwrap();
        let k: usize = 768;
        Keypair { p, q, y, k}
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair().keys();

        let p = RawPlaintext::from(BigInt::from(10));
        let c = JoyeLibert::encrypt(&ek, p.clone());

        let start_time = Instant::now();
        let recovered_p = JoyeLibert::decrypt(&dk, c);
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        assert_eq!(recovered_p, p);
        println!("{:?}", elapsed_time);
    }

    
    /*#[test]
    fn test_correct_keygen() {
        let (ek, dk): (EncryptionKey, _) = JoyeLibert::keypair_with_modulus_size(3072, 768).keys();

        let m = RawPlaintext::from(BigInt::from(10));
        let c = JoyeLibert::encrypt(&ek, m.clone()); // TODO avoid clone

        let recovered_m = JoyeLibert::decrypt(&dk, c);
        assert_eq!(recovered_m, m);
    }*/

    
}
