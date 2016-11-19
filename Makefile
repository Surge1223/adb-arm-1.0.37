TOOLCHAIN=
LD= $(TOOLCHAIN)ld
GXX=$(TOOLCHAIN)g++
CC=$(TOOLCHAIN)gcc
CXX=$(TOOLCHAIN)g++
AR=$(TOOLCHAIN)ar
RANLIB=$(TOOLCHAIN)ranlib

adb_host_srcs := \
 adb_client.cpp \
 client/main.cpp \
 console.cpp \
 commandline.cpp \
 file_sync_client.cpp \
 line_printer.cpp \
 services.cpp \
 shell_service_protocol.cpp \
	adb.cpp \
	adb_auth.cpp \
	adb_io.cpp \
	adb_listeners.cpp \
	adb_utils.cpp \
	sockets.cpp \
	transport.cpp \
	transport_usb.cpp \
	fdevent.cpp \
	get_my_path_linux.cpp \
	usb_linux.cpp \
	adb_auth_host.cpp \
	fdevent.cpp 

	

VPATH+= ../libcutils
SRCS+= socket_inaddr_any_server_unix.c
SRCS+= socket_local_client_unix.c
SRCS+= socket_local_server_unix.c
SRCS+= socket_loopback_client_unix.c
SRCS+= socket_loopback_server_unix.c
SRCS+= socket_network_client_unix.c
SRCS+= load_file.c
 

VPATH+= ../base
BASE+= file.cpp
BASE+= stringprintf.cpp
BASE+= strings.cpp

VPATH+= ../liblog
SRCS+= logd_write.c
SRCS+= log_event_write.c
SRCS+= fake_log_device.c
 
VPATH+= ../../../external/zlib/src
SRCS+= adler32.c
SRCS+= compress.c
SRCS+= crc32.c
SRCS+= deflate.c
SRCS+= infback.c
SRCS+= inffast.c
SRCS+= inflate.c
SRCS+= inftrees.c
SRCS+= trees.c
SRCS+= uncompr.c
SRCS+= zutil.c

VPATH+= ./crypto
LCRYPYO_SRCS := \
	cryptlib.c \
	mem.c \
	mem_clr.c \
	mem_dbg.c \
	cversion.c \
	ex_data.c \
	cpt_err.c \
	ebcdic.c \
	uid.c \
	o_time.c \
	o_str.c \
	o_dir.c \
  crypto/aes/aes_cbc.c \
  crypto/aes/aes_cfb.c \
  crypto/aes/aes_ctr.c \
  crypto/aes/aes_ecb.c \
  crypto/aes/aes_misc.c \
  crypto/aes/aes_ofb.c \
  crypto/aes/aes_wrap.c \
  crypto/asn1/a_bitstr.c \
  crypto/asn1/a_bool.c \
  crypto/asn1/a_bytes.c \
  crypto/asn1/a_d2i_fp.c \
  crypto/asn1/a_digest.c \
  crypto/asn1/a_dup.c \
  crypto/asn1/a_enum.c \
  crypto/asn1/a_gentm.c \
  crypto/asn1/a_i2d_fp.c \
  crypto/asn1/a_int.c \
  crypto/asn1/a_mbstr.c \
  crypto/asn1/a_object.c \
  crypto/asn1/a_octet.c \
  crypto/asn1/a_print.c \
  crypto/asn1/a_set.c \
  crypto/asn1/a_sign.c \
  crypto/asn1/a_strex.c \
  crypto/asn1/a_strnid.c \
  crypto/asn1/a_time.c \
  crypto/asn1/a_type.c \
  crypto/asn1/a_utctm.c \
  crypto/asn1/a_utf8.c \
  crypto/asn1/a_verify.c \
  crypto/asn1/ameth_lib.c \
  crypto/asn1/asn1_err.c \
  crypto/asn1/asn1_gen.c \
  crypto/asn1/asn1_lib.c \
  crypto/asn1/asn1_par.c \
  crypto/asn1/asn_mime.c \
  crypto/asn1/asn_moid.c \
  crypto/asn1/asn_pack.c \
  crypto/asn1/bio_asn1.c \
  crypto/asn1/bio_ndef.c \
  crypto/asn1/d2i_pr.c \
  crypto/asn1/d2i_pu.c \
  crypto/asn1/evp_asn1.c \
  crypto/asn1/f_enum.c \
  crypto/asn1/f_int.c \
  crypto/asn1/f_string.c \
  crypto/asn1/i2d_pr.c \
  crypto/asn1/i2d_pu.c \
  crypto/asn1/n_pkey.c \
  crypto/asn1/nsseq.c \
  crypto/asn1/p5_pbe.c \
  crypto/asn1/p5_pbev2.c \
  crypto/asn1/p8_pkey.c \
  crypto/asn1/t_bitst.c \
  crypto/asn1/t_crl.c \
  crypto/asn1/t_pkey.c \
  crypto/asn1/t_req.c \
  crypto/asn1/t_spki.c \
  crypto/asn1/t_x509.c \
  crypto/asn1/t_x509a.c \
  crypto/asn1/tasn_dec.c \
  crypto/asn1/tasn_enc.c \
  crypto/asn1/tasn_fre.c \
  crypto/asn1/tasn_new.c \
  crypto/asn1/tasn_prn.c \
  crypto/asn1/tasn_typ.c \
  crypto/asn1/tasn_utl.c \
  crypto/asn1/x_algor.c \
  crypto/asn1/x_attrib.c \
  crypto/asn1/x_bignum.c \
  crypto/asn1/x_crl.c \
  crypto/asn1/x_exten.c \
  crypto/asn1/x_info.c \
  crypto/asn1/x_long.c \
  crypto/asn1/x_name.c \
  crypto/asn1/x_nx509.c \
  crypto/asn1/x_pkey.c \
  crypto/asn1/x_pubkey.c \
  crypto/asn1/x_req.c \
  crypto/asn1/x_sig.c \
  crypto/asn1/x_spki.c \
  crypto/asn1/x_val.c \
  crypto/asn1/x_x509.c \
  crypto/asn1/x_x509a.c \
  crypto/bf/bf_cfb64.c \
  crypto/bf/bf_ecb.c \
  crypto/bf/bf_enc.c \
  crypto/bf/bf_ofb64.c \
  crypto/bf/bf_skey.c \
  crypto/bio/b_dump.c \
  crypto/bio/b_print.c \
  crypto/bio/b_sock.c \
  crypto/bio/bf_buff.c \
  crypto/bio/bf_nbio.c \
  crypto/bio/bf_null.c \
  crypto/bio/bio_cb.c \
  crypto/bio/bio_err.c \
  crypto/bio/bio_lib.c \
  crypto/bio/bss_acpt.c \
  crypto/bio/bss_bio.c \
  crypto/bio/bss_conn.c \
  crypto/bio/bss_dgram.c \
  crypto/bio/bss_fd.c \
  crypto/bio/bss_file.c \
  crypto/bio/bss_log.c \
  crypto/bio/bss_mem.c \
  crypto/bio/bss_null.c \
  crypto/bio/bss_sock.c \
  crypto/bn/bn_add.c \
  crypto/bn/bn_asm.c \
  crypto/bn/bn_blind.c \
  crypto/bn/bn_ctx.c \
  crypto/bn/bn_div.c \
  crypto/bn/bn_err.c \
  crypto/bn/bn_exp.c \
  crypto/bn/bn_exp2.c \
  crypto/bn/bn_gcd.c \
  crypto/bn/bn_gf2m.c \
  crypto/bn/bn_kron.c \
  crypto/bn/bn_lib.c \
  crypto/bn/bn_mod.c \
  crypto/bn/bn_mont.c \
  crypto/bn/bn_mpi.c \
  crypto/bn/bn_mul.c \
  crypto/bn/bn_nist.c \
  crypto/bn/bn_prime.c \
  crypto/bn/bn_print.c \
  crypto/bn/bn_rand.c \
  crypto/bn/bn_recp.c \
  crypto/bn/bn_shift.c \
  crypto/bn/bn_sqr.c \
  crypto/bn/bn_sqrt.c \
  crypto/bn/bn_word.c \
  crypto/buffer/buf_err.c \
  crypto/buffer/buffer.c \
  crypto/comp/c_rle.c \
  crypto/comp/c_zlib.c \
  crypto/comp/comp_err.c \
  crypto/comp/comp_lib.c \
  crypto/conf/conf_api.c \
  crypto/conf/conf_def.c \
  crypto/conf/conf_err.c \
  crypto/conf/conf_lib.c \
  crypto/conf/conf_mall.c \
  crypto/conf/conf_mod.c \
  crypto/conf/conf_sap.c \
  crypto/des/cbc_cksm.c \
  crypto/des/cbc_enc.c \
  crypto/des/cfb64ede.c \
  crypto/des/cfb64enc.c \
  crypto/des/cfb_enc.c \
  crypto/des/des_enc.c \
  crypto/des/des_old.c \
  crypto/des/des_old2.c \
  crypto/des/ecb3_enc.c \
  crypto/des/ecb_enc.c \
  crypto/des/ede_cbcm_enc.c \
  crypto/des/enc_read.c \
  crypto/des/enc_writ.c \
  crypto/des/fcrypt.c \
  crypto/des/fcrypt_b.c \
  crypto/des/ofb64ede.c \
  crypto/des/ofb64enc.c \
  crypto/des/ofb_enc.c \
  crypto/des/pcbc_enc.c \
  crypto/des/qud_cksm.c \
  crypto/des/rand_key.c \
  crypto/des/read2pwd.c \
  crypto/des/rpc_enc.c \
  crypto/des/set_key.c \
  crypto/des/str2key.c \
  crypto/des/xcbc_enc.c \
  crypto/dh/dh_ameth.c \
  crypto/dh/dh_asn1.c \
  crypto/dh/dh_check.c \
  crypto/dh/dh_depr.c \
  crypto/dh/dh_err.c \
  crypto/dh/dh_gen.c \
  crypto/dh/dh_key.c \
  crypto/dh/dh_lib.c \
  crypto/dh/dh_pmeth.c \
  crypto/dsa/dsa_ameth.c \
  crypto/dsa/dsa_asn1.c \
  crypto/dsa/dsa_depr.c \
  crypto/dsa/dsa_err.c \
  crypto/dsa/dsa_gen.c \
  crypto/dsa/dsa_key.c \
  crypto/dsa/dsa_lib.c \
  crypto/dsa/dsa_ossl.c \
  crypto/dsa/dsa_pmeth.c \
  crypto/dsa/dsa_prn.c \
  crypto/dsa/dsa_sign.c \
  crypto/dsa/dsa_vrf.c \
  crypto/dso/dso_dl.c \
  crypto/dso/dso_dlfcn.c \
  crypto/dso/dso_err.c \
  crypto/dso/dso_lib.c \
  crypto/dso/dso_null.c \
  crypto/dso/dso_openssl.c \
  crypto/dso/dso_vms.c \
  crypto/dso/dso_win32.c \
  crypto/ec/ec2_mult.c \
  crypto/ec/ec2_smpl.c \
  crypto/ec/ec_ameth.c \
  crypto/ec/ec_asn1.c \
  crypto/ec/ec_check.c \
  crypto/ec/ec_curve.c \
  crypto/ec/ec_cvt.c \
  crypto/ec/ec_err.c \
  crypto/ec/ec_key.c \
  crypto/ec/ec_lib.c \
  crypto/ec/ec_mult.c \
  crypto/ec/ec_pmeth.c \
  crypto/ec/ec_print.c \
  crypto/ec/eck_prn.c \
  crypto/ec/ecp_mont.c \
  crypto/ec/ecp_nist.c \
  crypto/ec/ecp_smpl.c \
  crypto/ecdh/ech_err.c \
  crypto/ecdh/ech_key.c \
  crypto/ecdh/ech_lib.c \
  crypto/ecdh/ech_ossl.c \
  crypto/ecdsa/ecs_asn1.c \
  crypto/ecdsa/ecs_err.c \
  crypto/ecdsa/ecs_lib.c \
  crypto/ecdsa/ecs_ossl.c \
  crypto/ecdsa/ecs_sign.c \
  crypto/ecdsa/ecs_vrf.c \
  crypto/err/err.c \
  crypto/err/err_all.c \
  crypto/err/err_prn.c \
  crypto/evp/bio_b64.c \
  crypto/evp/bio_enc.c \
  crypto/evp/bio_md.c \
  crypto/evp/bio_ok.c \
  crypto/evp/c_all.c \
  crypto/evp/c_allc.c \
  crypto/evp/c_alld.c \
  crypto/evp/digest.c \
  crypto/evp/e_aes.c \
  crypto/evp/e_bf.c \
  crypto/evp/e_des.c \
  crypto/evp/e_des3.c \
  crypto/evp/e_null.c \
  crypto/evp/e_old.c \
  crypto/evp/e_rc2.c \
  crypto/evp/e_rc4.c \
  crypto/evp/e_rc5.c \
  crypto/evp/e_xcbc_d.c \
  crypto/evp/encode.c \
  crypto/evp/evp_acnf.c \
  crypto/evp/evp_enc.c \
  crypto/evp/evp_err.c \
  crypto/evp/evp_key.c \
  crypto/evp/evp_lib.c \
  crypto/evp/evp_pbe.c \
  crypto/evp/evp_pkey.c \
  crypto/evp/m_dss.c \
  crypto/evp/m_dss1.c \
  crypto/evp/m_ecdsa.c \
  crypto/evp/m_md4.c \
  crypto/evp/m_md5.c \
  crypto/evp/m_mdc2.c \
  crypto/evp/m_null.c \
  crypto/evp/m_ripemd.c \
  crypto/evp/m_sha1.c \
  crypto/evp/m_sigver.c \
  crypto/evp/names.c \
  crypto/evp/p5_crpt.c \
  crypto/evp/p5_crpt2.c \
  crypto/evp/p_dec.c \
  crypto/evp/p_enc.c \
  crypto/evp/p_lib.c \
  crypto/evp/p_open.c \
  crypto/evp/p_seal.c \
  crypto/evp/p_sign.c \
  crypto/evp/p_verify.c \
  crypto/evp/pmeth_fn.c \
  crypto/evp/pmeth_gn.c \
  crypto/evp/pmeth_lib.c \
  crypto/hmac/hm_ameth.c \
  crypto/hmac/hm_pmeth.c \
  crypto/hmac/hmac.c \
  crypto/krb5/krb5_asn.c \
  crypto/lhash/lh_stats.c \
  crypto/lhash/lhash.c \
  crypto/md4/md4_dgst.c \
  crypto/md4/md4_one.c \
  crypto/md5/md5_dgst.c \
  crypto/md5/md5_one.c \
  crypto/modes/cbc128.c \
  crypto/modes/cfb128.c \
  crypto/modes/ctr128.c \
  crypto/modes/ofb128.c \
  crypto/objects/o_names.c \
  crypto/objects/obj_dat.c \
  crypto/objects/obj_err.c \
  crypto/objects/obj_lib.c \
  crypto/objects/obj_xref.c \
  crypto/ocsp/ocsp_asn.c \
  crypto/ocsp/ocsp_cl.c \
  crypto/ocsp/ocsp_err.c \
  crypto/ocsp/ocsp_ext.c \
  crypto/ocsp/ocsp_ht.c \
  crypto/ocsp/ocsp_lib.c \
  crypto/ocsp/ocsp_prn.c \
  crypto/ocsp/ocsp_srv.c \
  crypto/ocsp/ocsp_vfy.c \
  crypto/pem/pem_all.c \
  crypto/pem/pem_err.c \
  crypto/pem/pem_info.c \
  crypto/pem/pem_lib.c \
  crypto/pem/pem_oth.c \
  crypto/pem/pem_pk8.c \
  crypto/pem/pem_pkey.c \
  crypto/pem/pem_seal.c \
  crypto/pem/pem_sign.c \
  crypto/pem/pem_x509.c \
  crypto/pem/pem_xaux.c \
  crypto/pem/pvkfmt.c \
  crypto/pkcs12/p12_add.c \
  crypto/pkcs12/p12_asn.c \
  crypto/pkcs12/p12_attr.c \
  crypto/pkcs12/p12_crpt.c \
  crypto/pkcs12/p12_crt.c \
  crypto/pkcs12/p12_decr.c \
  crypto/pkcs12/p12_init.c \
  crypto/pkcs12/p12_key.c \
  crypto/pkcs12/p12_kiss.c \
  crypto/pkcs12/p12_mutl.c \
  crypto/pkcs12/p12_npas.c \
  crypto/pkcs12/p12_p8d.c \
  crypto/pkcs12/p12_p8e.c \
  crypto/pkcs12/p12_utl.c \
  crypto/pkcs12/pk12err.c \
  crypto/pkcs7/pk7_asn1.c \
  crypto/pkcs7/pk7_attr.c \
  crypto/pkcs7/pk7_doit.c \
  crypto/pkcs7/pk7_lib.c \
  crypto/pkcs7/pk7_mime.c \
  crypto/pkcs7/pk7_smime.c \
  crypto/pkcs7/pkcs7err.c \
  crypto/rand/md_rand.c \
  crypto/rand/rand_egd.c \
  crypto/rand/rand_err.c \
  crypto/rand/rand_lib.c \
  crypto/rand/rand_unix.c \
  crypto/rand/randfile.c \
  crypto/rc2/rc2_cbc.c \
  crypto/rc2/rc2_ecb.c \
  crypto/rc2/rc2_skey.c \
  crypto/rc2/rc2cfb64.c \
  crypto/rc2/rc2ofb64.c \
  crypto/rc4/rc4_enc.c \
  crypto/rc4/rc4_skey.c \
  crypto/ripemd/rmd_dgst.c \
  crypto/ripemd/rmd_one.c \
  crypto/rsa/rsa_ameth.c \
  crypto/rsa/rsa_asn1.c \
  crypto/rsa/rsa_chk.c \
  crypto/rsa/rsa_eay.c \
  crypto/rsa/rsa_err.c \
  crypto/rsa/rsa_gen.c \
  crypto/rsa/rsa_lib.c \
  crypto/rsa/rsa_none.c \
  crypto/rsa/rsa_null.c \
  crypto/rsa/rsa_oaep.c \
  crypto/rsa/rsa_pk1.c \
  crypto/rsa/rsa_pmeth.c \
  crypto/rsa/rsa_prn.c \
  crypto/rsa/rsa_pss.c \
  crypto/rsa/rsa_saos.c \
  crypto/rsa/rsa_sign.c \
  crypto/rsa/rsa_ssl.c \
  crypto/rsa/rsa_x931.c \
  crypto/sha/sha1_one.c \
  crypto/sha/sha1dgst.c \
  crypto/sha/sha256.c \
  crypto/sha/sha512.c \
  crypto/sha/sha_dgst.c \
  crypto/stack/stack.c \
  crypto/ts/ts_err.c \
  crypto/txt_db/txt_db.c \
  crypto/ui/ui_compat.c \
  crypto/ui/ui_err.c \
  crypto/ui/ui_lib.c \
  crypto/ui/ui_openssl.c \
  crypto/ui/ui_util.c \
  crypto/x509/by_dir.c \
  crypto/x509/by_file.c \
  crypto/x509/x509_att.c \
  crypto/x509/x509_cmp.c \
  crypto/x509/x509_d2.c \
  crypto/x509/x509_def.c \
  crypto/x509/x509_err.c \
  crypto/x509/x509_ext.c \
  crypto/x509/x509_lu.c \
  crypto/x509/x509_obj.c \
  crypto/x509/x509_r2x.c \
  crypto/x509/x509_req.c \
  crypto/x509/x509_set.c \
  crypto/x509/x509_trs.c \
  crypto/x509/x509_txt.c \
  crypto/x509/x509_v3.c \
  crypto/x509/x509_vfy.c \
  crypto/x509/x509_vpm.c \
  crypto/x509/x509cset.c \
  crypto/x509/x509name.c \
  crypto/x509/x509rset.c \
  crypto/x509/x509spki.c \
  crypto/x509/x509type.c \
  crypto/x509/x_all.c \
  crypto/x509v3/pcy_cache.c \
  crypto/x509v3/pcy_data.c \
  crypto/x509v3/pcy_lib.c \
  crypto/x509v3/pcy_map.c \
  crypto/x509v3/pcy_node.c \
  crypto/x509v3/pcy_tree.c \
  crypto/x509v3/v3_akey.c \
  crypto/x509v3/v3_akeya.c \
  crypto/x509v3/v3_alt.c \
  crypto/x509v3/v3_bcons.c \
  crypto/x509v3/v3_bitst.c \
  crypto/x509v3/v3_conf.c \
  crypto/x509v3/v3_cpols.c \
  crypto/x509v3/v3_crld.c \
  crypto/x509v3/v3_enum.c \
  crypto/x509v3/v3_extku.c \
  crypto/x509v3/v3_genn.c \
  crypto/x509v3/v3_ia5.c \
  crypto/x509v3/v3_info.c \
  crypto/x509v3/v3_int.c \
  crypto/x509v3/v3_lib.c \
  crypto/x509v3/v3_ncons.c \
  crypto/x509v3/v3_ocsp.c \
  crypto/x509v3/v3_pci.c \
  crypto/x509v3/v3_pcia.c \
  crypto/x509v3/v3_pcons.c \
  crypto/x509v3/v3_pku.c \
  crypto/x509v3/v3_pmaps.c \
  crypto/x509v3/v3_prn.c \
  crypto/x509v3/v3_purp.c \
  crypto/x509v3/v3_skey.c \
  crypto/x509v3/v3_sxnet.c \
  crypto/x509v3/v3_utl.c \
  crypto/x509v3/v3err.c 



arm_c_flags := \
	-DAES_ASM \
	-DGHASH_ASM \
	-DOPENSSL_BN_ASM_GF2m \
	-DOPENSSL_BN_ASM_MONT \
	-DSHA1_ASM \
	-DSHA256_ASM \
	-DSHA512_ASM \

ADBFLAGS += \
	-DADB_HOST=1 \
	-DALLOW_ADBD_ROOT=1 \
	-DADB_HOST_ON_TARGET=1 \


common_c_includes := \
  crypto \
  crypto/asn1 \
  crypto/evp \
  crypto/modes \
  include \
  include/openssl \

arm_src_files := \
  crypto/aes/asm/aes-armv4.S \
  crypto/bn/asm/armv4-gf2m.S \
  crypto/bn/asm/armv4-mont.S \
  crypto/chacha/chacha_vec_arm.S \
  crypto/modes/asm/ghash-armv4.S \
  crypto/poly1305/poly1305_arm.c \
  crypto/poly1305/poly1305_arm_asm.S \
  crypto/sha/asm/sha1-armv4-large.S \
  crypto/sha/asm/sha256-armv4.S \
  crypto/sha/asm/sha512-armv4.S \


libdl_stubs := \
	libdl.c
libdl_stubs_cflags := \
	-Wall -Wextra -Wunused  -Wno-unused-but-set-variable
libdl_stubs_ldflags := \
	-Wl,--exclude-libs=libgcc.a \
	-Wl,--version-script=$(LOCAL_PATH)/libdl.map



CPPFLAGS+= -I../../../external/openssl-android-master/crypto/asn1 
CPPFLAGS+= -I../../../external/openssl-android-master/crypto/evp 
CPPFLAGS+= -I../../../external/openssl-android-master/include/openssl
CPPFLAGS+= -DADB_HOST=1
CPPFLAGS+= -DHAVE_FORKEXEC=1
CPPFLAGS+= -DHAVE_SYMLINKS
CPPFLAGS+= -DHAVE_TERMIO_H
CPPFLAGS+= -DHAVE_SYS_SOCKET_H
CPPFLAGS+= -D_GNU_SOURCE
CPPFLAGS+= -D_XOPEN_SOURCE
CPPFLAGS+= -I.
CPPFLAGS+= -Iinclude
CPPFLAGS+= -I../include
CPPFLAGS+= -I../../../external/openssl-android-master/crypto
CPPFLAGS+= -I../../../external/openssl/crypto
CPPFLAGS+= -I../../../external/openssl
CPPFLAGS+= -I../base/include
CPPFLAGS += -DHAVE_ANDROID_OS=1
CPPFLAGS += -D'ADB_REVISION="7.0-N"' 


CXXFLAGS += \
	  -std=gnu++14 -O3 -D_GNU_SOURCE \
	  -Wall -fPIC  -fpermissive \
	  -Icore/base/include \
	  -DWORKAROUND_BUG6558362 -DFAKE_LOG_DEVICE=1 \
   -DLIBLOG_LOG_TAG='arm-adb' \
	  -I/opt/androideabi/include/c++/4.9.x \
	  -I/opt/androideabi/include/c++ \
	  -I/opt/androideabi/include/c++/4.9.x/arm-linux-androideabi \
	  $(libdl_stubs_cflags)  -Wno-unused-variable \
	  $(LOCAL_CFLAGS) \
    -Wall -Wextra -Werror \
    -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -Wvla \
    -DADB_HOST_ON_TARGET=1 \
    -DALLOW_ADBD_ROOT=1 \
    -fext-numeric-literals

LOCAL_CFLAGS += \
    -D_GNU_SOURCE \
    -DADB_HOST=1 \
    -fvisibility=hidden \
    $(ADB_COMMON_linux_CFLAGS) \
    -DHAVE_MACROS \
    -fPIC \
    -DHAVE_ANDROID_OS=1 \
    -D__ANDROID__ \
    -D_GNU_SOURCE \
    -D__USE_BSD \
    -DALLOW_ADBD_ROOT=1 \
    -DADB_HOST_ON_TARGET=1 \
    -I/data/toolchain/include/c++/4.9.3/arm-linux-androideabi 

CXXFLAGS += -I../include  -I../../../external/libcxx/include
CXXFLAGS += -I./include -I/data/toolchain/include 
CXXFLAGS += -I. -I/data/toolchain/include/c++/4.9.3
CXXFLAGS += -I/data/toolchain/include/c++/4.9.3/bits
CXXFLAGS += -I/data/toolchain/include/c++/4.9.3/arm-linux-androideabi 


CFLAGS += \
	   -O3 -std=c99 -D_GNU_SOURCE -Wall -fPIC \
	  -Wno-unused-parameter -I/opt/androideabi/sysroot/usr/include \
	  -DOPENSSL_NO_HW -DOPENSSL_NO_ENGINE \
	  -DZLIB $(arm_c_flags) $(ADBFLAGS) \
	  -Icrypto/include/openssl -Iinclude \
	  -Wno-unused-variable  $(libdl_stubs_cflags) \
	  $(CPPFLAGS) -Icore/include  \
	  -Icore/base/include \
   -DFAKE_LOG_DEVICE=1 \
   -DLIBLOG_LOG_TAG=1005 \
   -DSNET_EVENT_LOG_TAG=1397638484

LDFLAGS += \
	    -static -Wl,-rpath-link=/opt/androideabi/sysroot/usr/lib/ \
	    -nostdlib -L/opt/androideabi/sysroot/usr/lib \
	    --sysroot=/opt/androideabi/sysroot 

LDLIBS += \
	-L/data/toolchain/sysroot/usr/lib \
	-L./ -lc -lgcc -ldl -lc -lz -lm -lstdc++ \
	-lcutils -llog -lbase -lcrypto_static -lutils \
 -lziparchive

LDFLAGS+= -static -FPIE  -Wl,-rpath-link=/data/toolchain/sysroot/usr/lib/ \
-dynamic-linker,/system/bin/linker -L/data/toolchain/sysroot/usr/lib/crtend_android.o \
-L/data/toolchain/sysroot/usr/lib/libandroid.so -L/data/toolchain/sysroot/usr/lib/libc.so \
-L/data/toolchain/sysroot/usr/lib/crtbegin_dynamic.o -L/data/toolchain/sysroot/usr/lib \
-L/data/toolchain/sysroot/usr/lib/libc.so. -L/data/toolchain/lib -L/data/toolchain/lib/libdl.so
 
LDLIBS +=./libcrypto_static.a ./libdl.a ./libgcc.a -L/data/toolchain/sysroot/usr/lib  -static-libgcc 
LOCAL_STATIC_LIBRARIES := libz libcrypto_static

LDFLAGS+= -static -Wl,-rpath-link=/data/toolchain/sysroot/usr/lib/ -I/data/toolchain/sysroot/usr/include/ \
--sysroot=/data/toolchain/sysroot -dynamic-linker=/system/bin/linker -fPIC -fPIE -fpie -fpic 
 
DLOBJS += $(libdl_stubs:.c=.o)

OBJS += $(adb_host_srcs:.cpp=.o)
#OBJS += $(BASE:.cpp=.o)
#SRCOBJS += $(SRCS:.c=.o)

CPP_FILES += $(wildcard *.cpp)
CPP_FILES += $(wildcard ../base/*.cpp)

OBJ_FILES := $(addprefix obj/,$(notdir $(CPP_FILES:.cpp=.o)))
CRYPTOBJ_FILES += $(LCRYPYO_SRCS:.c=.o)

all: adb 


libcrypto_static: $(CRYPTOBJ_FILES)
	$(AR) rs libcrypto_static.a $^


others: $(SRCOBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $(LDLIBS)

adb:	$(OBJS)
	$(GXX) -o  $@ $^ $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDLIBS) 
 
clean:
	rm -rf $(OBJS) $(DLOBJS) $(CRYPTOBJ_FILES) *.o adb libdl.a libcrypto_static.a


test: $(OBJS)
	$(GXX)  $(LDFLAGS) -o $@ $(OBJS) $(CFLAGS) $(CPPFLAGS) $(LDLIBS)
