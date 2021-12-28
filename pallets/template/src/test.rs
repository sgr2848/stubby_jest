use crate::mock::*;
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;
#[test]
fn check_authenticate_signature() {
	new_test_ext().execute_with(|| {
        //Signature: /B8IGwJQDFxSm45EK9UnHv2OyiyffxTlLkEqrhSG8DMBpS3uq9Z1wrCYS9Gv4vmlvPrKObCgcica08YVmqgRqAA=
        //Raw message (Payload): 0x0398bc82113ca0b1dc2953d14297d962d245dc8223716985e985855f971d04b8
        //Signing wallet Address: hxb48f3bd3862d4a489fb3c9b761c4cfb20b34a645
        let signature = b"B8IGwJQDFxSm45EK9UnHv2OyiyffxTlLkEqrhSG8DMBpS3uq9Z1wrCYS9Gv4vmlvPrKObCgcica08YVmqgRqAA=".to_vec();
        let msg = b"0x0398bc82113ca0b1dc2953d14297d962d245dc8223716985e985855f971d04b8".to_vec();
        let pk = b"hxb48f3bd3862d4a489fb3c9b761c4cfb20b34a645".to_vec();
        assert_noop!(TemplateModule::authenticate_signature(Origin::signed(1),signature,msg,pk))
    });
}
