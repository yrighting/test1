use rust_joyelibert::*;

fn main() {
    let (ek, dk) = JoyeLibert::keypair().keys();

    //
    // Encryption
    //

    let c1 = JoyeLibert::encrypt(&ek, &*vec![1, 5, 10]);
    let c2 = JoyeLibert::encrypt(&ek, &*vec![2, 10, 20]);
    let c3 = JoyeLibert::encrypt(&ek, &*vec![3, 15, 30]);
    let c4 = JoyeLibert::encrypt(&ek, &*vec![4, 20, 40]);

    // add up all four encryptions
    let c = JoyeLibert::add(
        &ek,
        &JoyeLibert::add(&ek, &c1, &c2),
        &JoyeLibert::add(&ek, &c3, &c4),
    );

    let d = JoyeLibert::mul(&ek, &c, 2);

    //
    // Decryption
    //

    let m = JoyeLibert::decrypt(&dk, &c);
    let n = JoyeLibert::decrypt(&dk, &d);
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
    assert_eq!(m, vec![10, 50, 100]);
}
