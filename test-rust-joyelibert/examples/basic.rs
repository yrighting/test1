use rust_joyelibert::*;

fn main() {
    // first generate a fresh keypair, where
    // the encryption key can be made public
    // while the decryption key should remain private
    let (ek, dk) = JoyeLibert::keypair().keys();

    // after sharing the encryption key anyone can encrypt values
    let c1 = JoyeLibert::encrypt(&ek, 10);
    let c2 = JoyeLibert::encrypt(&ek, 20);
    let c3 = JoyeLibert::encrypt(&ek, 30);
    let c4 = JoyeLibert::encrypt(&ek, 40);

    // and anyone can perform homomorphic operations on encrypted values,
    // e.g. multiplication with unencrypted values
    let d1 = JoyeLibert::mul(&ek, c1, 4);
    let d2 = JoyeLibert::mul(&ek, c2, 3);
    let d3 = JoyeLibert::mul(&ek, c3, 2);
    let d4 = JoyeLibert::mul(&ek, c4, 1);
    // ... or addition with encrypted values
    let d = JoyeLibert::add(&ek, JoyeLibert::add(&ek, d1, d2), JoyeLibert::add(&ek, d3, d4));

    // // after all homomorphic operations are done the result
    // // should be re-randomized to hide all traces of the inputs
    // let d = JoyeLibert::rerandomize(&ek, d);

    // finally, only the one with the private decryption key
    // can retrieve the result
    let m = JoyeLibert::decrypt(&dk, &d);
    println!("Decrypted value is {}", m);
}
