import datetime
import unittest

from jwcrypto import jwk
from ecdsa import SigningKey, SECP256k1

from mykeepin.did.verifier import DidVerifier
from mykeepin.verifiable.sign import VerifiableSignedJWT
from mykeepin.verifiable.encryption import VerifiableEncryptJWE
from mykeepin.verifiable.credential import VerifiableCredential
from mykeepin.verifiable.presentation import VerifiablePresentation

AA_KID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000003b1#MetaManagementKey#e3502768c10cea0b8ee6612b3abfe260b345d263"
AA_DID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000003b1"
AA_PRIVATE = "a5fd63f2fa3bff5cc9edd33e1284b3ff77ce56e32824fb7fa91ae1afbe680a0b"
AA_PRIVATE_JWK = jwk.JWK().from_pem(
    SigningKey.from_string(bytes.fromhex(AA_PRIVATE), curve=SECP256k1).to_pem()
)
SP_RSA_PRIVATE = '{"p": "_X1MpwOUOqz5jv6suQILzoXwL-bXb4E5oz95GocSwti04zYZgudcIy787DxwEis1pD8GhYDFW_Ryx4JK3AfdghtvocC7DRjWUzMgPvPR69unbSby7jRghATSWQuDamCJ_5l5tO7c5DA9hIB0FIr8QfkBkDPSh1jZMpk0hORk_m8", "kty": "RSA", "q": "yIfcL9IeLSbByjsKYoRq_KZ6ncAx8le1GWwJ4evKJ-IaGGF_CaZH7EmAsuyMaW7tTdc8OBI7kCNKn9MyZPTd704rOgUI-cTfnb9AFMVgs66KECN0XF8RBrgrw83BUoEvkRp477dM1fVWpL9bUpZKpQ-gDCsustgQFceauIHi4Zc", "d": "rflpFBXz9GKv-k3Sulc5AZfhrpE8YzI0YevgjKCidsgINnK33urJa9MwWeGqmvtbZNO5JKiA3rywXU_qXjig76-s6cwARkd8nR1oMz6RM0DsBq4elVm-bpwW9dOOd-NZvx-V0-OwM2AzC4d3LMQJzg9HDEn0CgM_U5naP9ryY7nsppWiYqyOW5TwgB37qOV0PWgTRfpWXu_FXsYmTLvwfJ0nnI5ymlTazZX6why9OI-CqvI76e46lt2ZqQ3u-Zz9JxSpkWbuBLLct7cRqDtiJuTaJMG7qmFqR72Ufu95M6ZhSRCrrvpj6nk4dZcru0L4kPJhGpnpjcOE_ZdNf_X85Q", "e": "AQAB", "qi": "3Lyv2sSHPJzO2ZQ-GkiMBACzXYWIv7YnxyqAoriYV16pJgnOvEKHk_mRLlabiPCBkevFyHe-4faxqbnvrcbv_6wDrAhXrc-AurdQT76QNTYlZyaSUp5-iuykPGkU9RYR6XKQBtHaR7ms25Q8W8CjtcMC8M2iCrT7IQZWaPfzQQ4", "dp": "QQjal6bVatBiHou8aKLbwJqgasnAz_zJetaYDXRGHfNXRUvl863D98rgXQOMhTzMwFzjIXFOMS9gG0uURStHa0_6rfcyhkOvCR1-0mffnbF3HQv3G6IYeQZ7qRjJGIu4G_mWPhNiXLD7t3j1TyfxXEO0YPjKtKrY3qBr1wR53MU", "dq": "t-ghf5nsIuyQfa937rISjHMBsPs6006swAvdZFyiocEyvXls0KS3AXTHm1Bl1avt5p2mlKXkCmTTY5CFfyEzCO1fp25GtQphKoLjeikqbp977yEU7kIhk1AEkyZ4Tfo8bY8hqnco-HBwbdcxIaTEAG08Euznfw24csEEnIJCWTE", "n": "xpBq_O7N9QSCSzOi26Iop4dtMLF0F3HCsu43yxytGq9k2CtTwaYvQr0vK0tsWBGu7BSx_q3DurUHmfWunCJTPOPErO6-A5MR5NKCSIfxxvhQrPS2d4dJPzm4PSS3JPsUs7YIOkkgG-SVVX_Dvh7jv4mugl_BvoEgklgvOtv9zPX3FOBVcD5bLxe2JCA5bAyTRTBczeOU9D_LcVeTdIkvw7XMgbyzvH2fH50RULUchE62uy-mQzSEGCsv6Un7ybc5c8cmbnYJA2e0UQVDc7TXyXYIDtOhPuxm-XbhUb_b28n8IKwTefNLl_9Ffwb2r0gIu89iaJ8VP4ag3fJGCC-ieQ"}'
SP_RSA_PRIVATE_JWK = jwk.JWK().from_json(SP_RSA_PRIVATE)

USER_DID = "did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4"
USER_PRIVATE = "477cdbbe5a3774758e832ed99a3d91a5790090942d73a619aa6b223c4be014f5"


def decrypt_vp_data(verifier: DidVerifier, raw_vp):
    verified_claims = verifier.verify_jws(raw_vp, verifier.document)
    verifier.extract_credentials_from_presentation(verified_claims.claims)

    name_vc = verifier.find_verifiable_credential(AA_DID, "NameCredential")
    email_vc = verifier.find_verifiable_credential(AA_DID, "EmailCredential")

    print(f'이름 {name_vc["vc"]["credentialSubject"]["name"]}')
    print(f'이메일 {email_vc["vc"]["credentialSubject"]["email"]}')


class TestAA(unittest.TestCase):
    def test_issue_vc(self):
        name_vc = VerifiableCredential(
            id_="http://aa.metadium.com/credential/343", types=["NameCredential"], issuer=AA_DID,
            credential_subject={'id': USER_DID, 'name': '이인용'},
            issuance_date=datetime.datetime.now()
        )
        signed_vc1 = VerifiableSignedJWT().sign(verifiable=name_vc, kid=AA_KID, nonce='', key=AA_PRIVATE_JWK)

        name_vc = VerifiableCredential(
            types=["EmailCredential"], issuer=AA_DID,
            credential_subject={'id': USER_DID, 'email': 'inyong@coinplug.com'},
            issuance_date=datetime.datetime.now()
        )
        signed_vc2 = VerifiableSignedJWT().sign(verifiable=name_vc, kid=AA_KID, nonce='', key=AA_PRIVATE_JWK)
        return [signed_vc1, signed_vc2]

    def test_issue_vp(self):
        vp = VerifiablePresentation(
            issuer=AA_DID, types=["UserPresentation"], verifiable_credentials=self.test_issue_vc()
        )
        signed_vp = VerifiableSignedJWT().sign(verifiable=vp, kid=AA_KID, nonce='', key=AA_PRIVATE_JWK)
        return signed_vp

    def test_self_encrypt_vp(self):
        enc = VerifiableEncryptJWE(key=SP_RSA_PRIVATE_JWK.public())
        return enc.encrypt(self.test_issue_vp())

    def test_self_decrypt_vp(self):
        ve = VerifiableEncryptJWE(key=SP_RSA_PRIVATE_JWK)
        vp = ve.decrypt(self.test_self_encrypt_vp())

        verifier = DidVerifier(did=AA_DID)
        decrypt_vp_data(verifier, vp)

    def test_decrypt_vp(self):
        """Java 라이브러리에서 encrypt된 JWE를 decrypt"""
        enc_vp = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.aLWjfcaHIxrthLLQIattOVVbBVY2XF1oZ-forujYZUb7qc-Biy7q5Dy0Xzn_FqwHgKPHE_POVEGpasIMQEZb0iU_UPj2U9fZlf1-dGeMj9dxlqVEG6frIS3GGznNIw8MOToRQ4bCL-jeYEAqGo7ucME-feZ8Q2bCf8BYx-K8GzUaePvAmYLUQs_vBldUR_9CXp3MfqcGpe_C7HjO_HLhHaZni9vzy877Iho2vPQWjEewRyH4DsENwMMbG27OpVFjrdxvHXDUZA5SnIkXIwAeiSMxRxLGTNK0ogIgYmpRy6AvxhS9BjVHuJDdrhFCoBkH_yHRklCoy7an00t9DasTYA.YU_dnmevQtASN2QXHXsNhA.mWbSb6P53J7izJyGmNQKbIW3f_g8Tlh2PmcvkQyBmV12yvk8pMdp9H5AFqmo2RLSht6a91M7iFsXXDwHMnw8_aCbP9Rp1ladYXFmSxy_7dDniSUeCvZQLEFusy0YbX--YfDS24YG6jpZbEdkDlgESCcJ9m5amCbHdXMuT5ZKHW-b6Pq0abAys7JuyEdp-iyfV7j0FvMT1iXXMoZweUVrAmB8p1m1p_TWGQi0nOb7TIKXsezaAugewSZgYjG4JGk-tNvmsAOeoFQq5NuMpaKSpmwNKJNwQW7X2Nor2LwTP5jV9fmKNN1LTm4-EgyTYOLmBiVvQ4ugEWYN4DNlVdK1FdBddGIX1cL3EdsGS9SELZmS9HZfcyFeyiI8B2KFc1D1Pg-kdcI53TbleTaglizWQUBhJ5o0ZmGykuUVRy4ttlW8pVTPk_e4AIlBCszCkCxI_5WrKZcFGkPDXSLd_SV1Xl2t1uX5dPb-JO4U0yJUCFjhG7ZuVkONdvLU-fhxoiIh5qHAsn8OGa4ptLFeNHzoIL5Hi7FaMpKHwKSf7qTG4v83XRgVH_PuAuBC0FlM7mfQkjV0Wd4pxXIqZd3PBFl0TsZwTHUj93VwfZMhsNk6ocs7VINMw90MjyGLz_gQ_993AyKFsa106k0BNpmBG7_odSUWid8Gg3S5RL3UIxKXvoo5gapix60mOvnDv-GrrMCFz9G11Pk2PPJ3NOk-bcVO2GH4MMqOnINYK_sy5Vpz_WbmtZFrERHZUAS4nhFk33KC0cIG7C6DCJ7oBphaZlf-ZMkUJU09JO2NFh4I1nQZvVicuLZxILqmIeq0tteAPs1zUBr8DdAWd-9gyLz-etU2_i0MPiRV71lHBz4VKV1HzZzrXqKLl4j06MnkpMz_f4bLKAcyyWVgkqhflGkTwTKEW1J0K1Lppl-VAg1zlD-pPkFTm2geEeOeBG8SQQKTFXzrf7xlu6TG9SJPONi8wXI7YY4jMSiCm9gS2dzyy27gyXAR4UYjGkLuCVK-KRnU7bCeo0A3aUKJnDE6MK_wlKGAt8zqRmlX3PylJQBkEjsAqUJNtpQQT_LWR1pkMhoGtGoqZ7f6PdJS5T9H0PTD3cFpbos5ECxyhVb4XDzbl_eMU1s9CC-5nO0VaqUD0GGobiLzvGIH8jod2Qhv-Pchh3O0DG1mJAsCS5BvW0KzoBHy0ih1CmaKb78pfZ8OPuQarQKTnyJZ5sw1sd1GgkYDER-Xipj6mvkSVIGXjhK8mcJQzOhWkPIC6QJOFw3-NewFUf7MaSR8cVvGf24NN0duc7nCqiV9BXtEXOz-x33DS9Fy87wOF8MDDAHe1JS0emVE3N9UWjlzwvG6MfNIhKzRbeYrFhQo_5_kTajCvy7_MasNwM0P_TC2_704ZG8S9TPhJOnxU9URiHUiyHHHHmkjleNcgq_u45KHwGey-2pTHiSDPXG9Iq5VyBcpKpCPN3kquxh-dDfUvOad5d7FvaGXXG-rmyqbTSo4TDoX7ecGDkg3R1KU-APgFiyfOrhvxOAPCcFqsUWKY-5RHiQ4yQsGWu0s_76TPmZ4cCP1iMNr4roRhD4nKfVlPEq6oDhJIjd7K8VuJlIcQ8r58NYpFJvszQxkS-tJyD6hrecYOYUK117Pv8K6xBxNUvCY-vttsgidLYeI-GEpgdpdr5v0UbBAs3F-zCav9s37pAxUx0olrPg4tYIFQl6WeJzPNDLKHMMcELQqOkpkwQfeMsadkagl_-LDzw24b9FEcZPQcmKqcSZroqyrFJ9IFq512eR8HeI4CfSPgr3sziyEJv3mKLV226KDqfztlbbt82ILw6R-fepLVMBhxmBJYhv5cPgAyXc5fWi0ya9raPAuBOcoTvITYXu-oNIXETyKOJ7eVuyofZE1q5u9AOOx9urcED_uxoe-7O96TAqSQEqSB2BxFH03zekszsi48U-QtwFVsS3BVKYFBcFyJgzQP95qNmN6hb-rDkjJIIcCyHSMpR8Umbzb_bYkHHsjUp6rb8OWlKl1pbUGtP1-oUqorhYa4un1V-qbuyfiiCuVgb2dg6lBTl0exqZvTzDPy_J1CIhmHrxKWhNWYzPHOSpU4AMj0wbV00QSYF6X3LKf5UVN9yFQuiJphGVUgrhgHoNDasRIIEb4zTIAOij0pgrOWlg1_dDf3JRa-eyS9Bv3k785BJXvagkR2n8rrhrcj86RKOFg3ye5GAIim6tYtBWFzEfmPng078FfzkO3-v4K2wjWhVimlixner2BU7ml26whqcvlZJdTfAW4yn6ieLeYyFoYg5pYFX5DKnwNmbEU0urSRLmGxLCFtCf-CB7ePF-1GC_RECvnyQMPs1BPkJO6Twq_SQASoZUQOW3NVEQWbTaWtKfPNdZH8iErHXUbIcsF5rpR4HFxx8lA_TObKx_8oB28Fu9qDJFShXP2-11XOHgTuPvUXnij_hasTHJM6q8oT_DQU3-M-0wz_YgKuMTi8C0sV0OatFHOGv2WyAhB268vL-Qj2XwP7Rc9x5LfSy5TcJofENg_7E5PPHxed6dCHuuFoeih9agRLXDBXfbPzGJho6OSrPp1TFziqIxAEa7Z_9lBpUiR682u0RRKsQje--hbV7BJ3-ETnUqo0dTiLRo56KNBjggv9AuRgKOcMkzuI9ReMLyT8z_SSpIoY0FOLijkkkr4X3EXGheIDUuCBTuJLZB7DbLy6lscAaSc-88sln1SuvKw3HAULFvE9nPTF0_iDEmU-gACzUzPvTYF0fXGm3bKcNNuOoN_s9c_c6zRRPpOcNtnQv3br3A0JQAnagPKctQVZfL4FKAtWt5MTVKvUiGD6putK6a_kjcLB2RUHbOeVpQIrLcWX1TUKMgGXdMnqPbKUcAwjCeriRl02BMuBuzoqPPgIC4RmOtp4xXTJQ7HNP4gFKHzJbbZFwGuP0n6zzNtbAhYN3pEW8y_3I8BM8obOYq8285kaANgVlINrkWeL3V_lBnHznqPo0ZgrxoQY_qI2HA51UWNRV1X4iwDMh5_IFmnOl_Jrw8z4JRZWUXDdZoQ7StXPucaBHXHvxWFjJSdfUX_FEnEPpn_QyRsC4vb0rVClFetqHptVNFNg1zr4JRrDwFgi50j5s7xOBOtiTYJJa4NChsH0RMjvM5W-26N5FuNqH-nZh0hV_5GjJF7Qt9puLazAmRDI2KZBpbbXvaUG63-a1jw00FyVjRFT0d_NWw1GnABZJ2g6c1mJkvai-O6-i5EDwPwq_tklvp9PP753ZLdcHVs1ms4zwv37Pp47X34Ji-a_bJeP2huK2xS2AsZv3OD_J_vPOJg-x9WYZ8Vd-gOk_x2H-YsHncI0vhMi4YbZwNdBcfP_ObnoqRISYx6VQtwLB7fuomo46m-Pz1GKfP8dYewaP0caOWGIRjSQPnOND65iUM1evfbkOACRF2FfJGcId9yWMbOFL_CzqcqY5APs0j9SE3kgVKwFwI7_GZ4hMraoDXNolaGDdvKMyWSFEKg8ScwfR74IJENXvREaXh2urgzUS_Cd_Vc4u75TFM8KbjS6Coh-BVwfeQV6VENnyImQj3mxzZU_d1EXsRDuBW2jQ_RTP2vo9Zx7pMcEMIr4JsMv6EH4_I97SPgZnLh39_hcc4YgCMLJ7tjCX6b2bn8ZtOl4NsfJsw2l9FytK6L-CCtElVNTUySYTpNk_inrgfcJ_lLkk6rqj1wz8dgNldCvXNT4Ov2UHm7Tjm8Elbg-7Z82vEc6PCMqO-tejFNFWUHIESkJE9pBUgvh2AuNXEE1GuKzqgblehAO3Rp9ZXpFvnj6A2JzbS9ACxeIpXdC7vJY5K5BixK1-JBCiswOX84lissFVrBzZR_gnAEaQCK6z11K52EhSN0wFxOPfvdUuJlQBNHfxoS61Ut2F6R-RpfyNOPCwx5ptmEioZ0Ze2tRxPzxZWpktxj1TP0F_AvEs8YnMZAvZrdaWZYLZQMjrrZKPKE7XSlK7AE6M53SJwnm2QWhM4yx0aYq6ybCUwIwbvCQPy0OQD3UKuBWH1bvS-4pkey70Tj0TRnYmUIITUuiyedSgGlwvRiR2y5GfRIWVo3aPMvzWigjh35cSYywzNuvPky.mBtUMNr04KgwTAbUvKKKlw"

        ve = VerifiableEncryptJWE(key=SP_RSA_PRIVATE_JWK)
        vp = ve.decrypt(enc_vp)

        verifier = DidVerifier(did="did:meta:testnet:00000000000000000000000000000000000000000000000000000000000009b4")
        decrypt_vp_data(verifier, vp)

