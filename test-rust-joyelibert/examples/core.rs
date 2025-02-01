// use kzen_paillier::*;
use rust_joyelibert::*;

fn main() {
    // generate a fresh keypair
    let (ek, dk) = JoyeLibert::keypair().keys();

    // encrypt two values
    let c1 = JoyeLibert::encrypt(&ek, RawPlaintext::from(BigInt::from(20)));
    let c2 = JoyeLibert::encrypt(&ek, RawPlaintext::from(BigInt::from(30)));

    // add all of them together
    let c = JoyeLibert::add(&ek, c1, c2);

    // multiply the sum by 2
    let d = JoyeLibert::mul(&ek, c, RawPlaintext::from(BigInt::from(2)));

    // decrypt final result
    let m: BigInt = JoyeLibert::decrypt(&dk, d).into();
    println!("decrypted total sum is {}", m);
}
