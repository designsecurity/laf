<?php

namespace laf\Tools;

class CloudflareMITMEngine
{ 
    private $ciphers;
    
    public function __construct()
    {
        $this->ciphers["TLS_NULL_WITH_NULL_NULL"] = 0x0000;
        $this->ciphers["TLS_RSA_WITH_NULL_MD5"] = 0x0001;
        $this->ciphers["TLS_RSA_WITH_NULL_SHA"] = 0x0002;
        $this->ciphers["TLS_RSA_EXPORT_WITH_RC4_40_MD5"] = 0x0003;
        $this->ciphers["TLS_RSA_WITH_RC4_128_MD5"] = 0x0004;
        $this->ciphers["TLS_RSA_WITH_RC4_128_SHA"] = 0x0005;
        $this->ciphers["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"] = 0x0006;
        $this->ciphers["TLS_RSA_WITH_IDEA_CBC_SHA"] = 0x0007;
        $this->ciphers["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"]  = 0x0008;
        $this->ciphers["TLS_RSA_WITH_DES_CBC_SHA"] = 0x0009;
        $this->ciphers["TLS_RSA_WITH_3DES_EDE_CBC_SHA"] = 0x000A;
        $this->ciphers["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"]  = 0x000B;
        $this->ciphers["TLS_DH_DSS_WITH_DES_CBC_SHA"] = 0x000C;
        $this->ciphers["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"] = 0x000D;
        $this->ciphers["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = 0x000E;
        $this->ciphers["TLS_DH_RSA_WITH_DES_CBC_SHA"] = 0x000F;
        $this->ciphers["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"] = 0x0010;
        $this->ciphers["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"] = 0x0011;
        $this->ciphers["TLS_DHE_DSS_WITH_DES_CBC_SHA"] = 0x0012;
        $this->ciphers["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] = 0x0013;
        $this->ciphers["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] = 0x0014;
        $this->ciphers["TLS_DHE_RSA_WITH_DES_CBC_SHA"] = 0x0015;
        $this->ciphers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] = 0x0016;
        $this->ciphers["TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5"] = 0x0017;
        $this->ciphers["TLS_DH_Anon_WITH_RC4_128_MD5"] = 0x0018;
        $this->ciphers["TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA"] = 0x0019;
        $this->ciphers["TLS_DH_Anon_WITH_DES_CBC_SHA"] = 0x001A;
        $this->ciphers["TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA"] = 0x001B;
        $this->ciphers["SSL_FORTEZZA_KEA_WITH_NULL_SHA"] = 0x001C;
        $this->ciphers["SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"]= 0x001D;
        $this->ciphers["TLS_KRB5_WITH_DES_CBC_SHA"] = 0x001E;
        $this->ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA"] = 0x001F;
        $this->ciphers["TLS_KRB5_WITH_RC4_128_SHA"] = 0x0020;
        $this->ciphers["TLS_KRB5_WITH_IDEA_CBC_SHA"] = 0x0021;
        $this->ciphers["TLS_KRB5_WITH_DES_CBC_MD5"] = 0x0022;
        $this->ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5"] = 0x0023;
        $this->ciphers["TLS_KRB5_WITH_RC4_128_MD5"] = 0x0024;
        $this->ciphers["TLS_KRB5_WITH_IDEA_CBC_MD5"] = 0x0025;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"] = 0x0026;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"] = 0x0027;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_SHA"] = 0x0028;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"] = 0x0029;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"] = 0x002A;
        $this->ciphers["TLS_KRB5_EXPORT_WITH_RC4_40_MD5"] = 0x002B;
        $this->ciphers["TLS_PSK_WITH_NULL_SHA"] = 0x002C;
        $this->ciphers["TLS_DHE_PSK_WITH_NULL_SHA"] = 0x002D;
        $this->ciphers["TLS_RSA_PSK_WITH_NULL_SHA"] = 0x002E;
        $this->ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"] = 0x002F;
        $this->ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA"] = 0x0030;
        $this->ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA"] = 0x0031;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA"] = 0x0032;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"] = 0x0033;
        $this->ciphers["TLS_DH_Anon_WITH_AES_128_CBC_SHA"] = 0x0034;
        $this->ciphers["TLS_RSA_WITH_AES_256_CBC_SHA"] = 0x0035;
        $this->ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA"] = 0x0036;
        $this->ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA"] = 0x0037;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA"] = 0x0038;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"] = 0x0039;
        $this->ciphers["TLS_DH_Anon_WITH_AES_256_CBC_SHA"] = 0x003A;
        $this->ciphers["TLS_RSA_WITH_NULL_SHA256"] = 0x003B;
        $this->ciphers["TLS_RSA_WITH_AES_128_CBC_SHA256"] = 0x003C;
        $this->ciphers["TLS_RSA_WITH_AES_256_CBC_SHA256"] = 0x003D;
        $this->ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA256"] = 0x003E;
        $this->ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA256"] = 0x003F;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"] = 0x0040;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"] = 0x0041;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = 0x0042;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = 0x0043;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"] = 0x0044;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"] = 0x0045;
        $this->ciphers["TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA"] = 0x0046;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA"] = 0x0047;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA"] = 0x0048;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_DES_CBC_SHA"] = 0x0049;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = 0x004A;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"] = 0x004B;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"] = 0x004C;
        $this->ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"] = 0x0060;
        $this->ciphers["TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= 0x0061;
        $this->ciphers["TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"] = 0x0062;
        $this->ciphers["TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"] = 0x0063;
        $this->ciphers["TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"] = 0x0064;
        $this->ciphers["TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"] = 0x0065;
        $this->ciphers["TLS_DHE_DSS_WITH_RC4_128_SHA"] = 0x0066;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"] = 0x0067;
        $this->ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA256"] = 0x0068;
        $this->ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA256"] = 0x0069;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"] = 0x006A;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"] = 0x006B;
        $this->ciphers["TLS_DH_Anon_WITH_AES_128_CBC_SHA256"] = 0x006C;
        $this->ciphers["TLS_DH_Anon_WITH_AES_256_CBC_SHA256"] = 0x006D;
        $this->ciphers["TLS_GOSTR341094_WITH_28147_CNT_IMIT"] = 0x0080;
        $this->ciphers["TLS_GOSTR341001_WITH_28147_CNT_IMIT"] = 0x0081;
        $this->ciphers["TLS_GOSTR341094_WITH_NULL_GOSTR3411"] = 0x0082;
        $this->ciphers["TLS_GOSTR341001_WITH_NULL_GOSTR3411"] = 0x0083;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"] = 0x0084;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = 0x0085;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = 0x0086;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"] = 0x0087;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"] = 0x0088;
        $this->ciphers["TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA"] = 0x0089;
        $this->ciphers["TLS_PSK_WITH_RC4_128_SHA"] = 0x008A;
        $this->ciphers["TLS_PSK_WITH_3DES_EDE_CBC_SHA"] = 0x008B;
        $this->ciphers["TLS_PSK_WITH_AES_128_CBC_SHA"] = 0x008C;
        $this->ciphers["TLS_PSK_WITH_AES_256_CBC_SHA"] = 0x008D;
        $this->ciphers["TLS_DHE_PSK_WITH_RC4_128_SHA"] = 0x008E;
        $this->ciphers["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"] = 0x008F;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"] = 0x0090;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"] = 0x0091;
        $this->ciphers["TLS_RSA_PSK_WITH_RC4_128_SHA"] = 0x0092;
        $this->ciphers["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"] = 0x0093;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"] = 0x0094;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"] = 0x0095;
        $this->ciphers["TLS_RSA_WITH_SEED_CBC_SHA"] = 0x0096;
        $this->ciphers["TLS_DH_DSS_WITH_SEED_CBC_SHA"] = 0x0097;
        $this->ciphers["TLS_DH_RSA_WITH_SEED_CBC_SHA"] = 0x0098;
        $this->ciphers["TLS_DHE_DSS_WITH_SEED_CBC_SHA"] = 0x0099;
        $this->ciphers["TLS_DHE_RSA_WITH_SEED_CBC_SHA"] = 0x009A;
        $this->ciphers["TLS_DH_Anon_WITH_SEED_CBC_SHA"] = 0x009B;
        $this->ciphers["TLS_RSA_WITH_AES_128_GCM_SHA256"] = 0x009C;
        $this->ciphers["TLS_RSA_WITH_AES_256_GCM_SHA384"] = 0x009D;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] = 0x009E;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"] = 0x009F;
        $this->ciphers["TLS_DH_RSA_WITH_AES_128_GCM_SHA256"] = 0x00A0;
        $this->ciphers["TLS_DH_RSA_WITH_AES_256_GCM_SHA384"] = 0x00A1;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"] = 0x00A2;
        $this->ciphers["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"] = 0x00A3;
        $this->ciphers["TLS_DH_DSS_WITH_AES_128_GCM_SHA256"] = 0x00A4;
        $this->ciphers["TLS_DH_DSS_WITH_AES_256_GCM_SHA384"] = 0x00A5;
        $this->ciphers["TLS_DH_Anon_WITH_AES_128_GCM_SHA256"] = 0x00A6;
        $this->ciphers["TLS_DH_Anon_WITH_AES_256_GCM_SHA384"] = 0x00A7;
        $this->ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256"] = 0x00A8;
        $this->ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384"] = 0x00A9;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"] = 0x00AA;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"] = 0x00AB;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"] = 0x00AC;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"] = 0x00AD;
        $this->ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256"] = 0x00AE;
        $this->ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384"] = 0x00AF;
        $this->ciphers["TLS_PSK_WITH_NULL_SHA256"] = 0x00B0;
        $this->ciphers["TLS_PSK_WITH_NULL_SHA384"] = 0x00B1;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"] = 0x00B2;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"] = 0x00B3;
        $this->ciphers["TLS_DHE_PSK_WITH_NULL_SHA256"] = 0x00B4;
        $this->ciphers["TLS_DHE_PSK_WITH_NULL_SHA384"] = 0x00B5;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"] = 0x00B6;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"] = 0x00B7;
        $this->ciphers["TLS_RSA_PSK_WITH_NULL_SHA256"] = 0x00B8;
        $this->ciphers["TLS_RSA_PSK_WITH_NULL_SHA384"] = 0x00B9;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BA;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BB;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BC;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BD;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BE;
        $this->ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"] = 0x00BF;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C0;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C1;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C2;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C3;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C4;
        $this->ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"] = 0x00C5;
        $this->ciphers["TLS_RENEGO_PROTECTION_REQUEST"] = 0x00FF;
        $this->ciphers["TLS_FALLBACK_SCSV"] = 0x5600;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA"] = 0xC001;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_RC4_128_SHA"] = 0xC002;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = 0xC003;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"] = 0xC004;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"] = 0xC005;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_NULL_SHA"] = 0xC006;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"] = 0xC007;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"] = 0xC008;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = 0xC009;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = 0xC00A;
        $this->ciphers["TLS_ECDH_RSA_WITH_NULL_SHA"] = 0xC00B;
        $this->ciphers["TLS_ECDH_RSA_WITH_RC4_128_SHA"] = 0xC00C;
        $this->ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"] = 0xC00D;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"] = 0xC00E;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"] = 0xC00F;
        $this->ciphers["TLS_ECDHE_RSA_WITH_NULL_SHA"] = 0xC010;
        $this->ciphers["TLS_ECDHE_RSA_WITH_RC4_128_SHA"] = 0xC011;
        $this->ciphers["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"] = 0xC012;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"] = 0xC013;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"] = 0xC014;
        $this->ciphers["TLS_ECDH_Anon_WITH_NULL_SHA"] = 0xC015;
        $this->ciphers["TLS_ECDH_Anon_WITH_RC4_128_SHA"] = 0xC016;
        $this->ciphers["TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA"] = 0xC017;
        $this->ciphers["TLS_ECDH_Anon_WITH_AES_128_CBC_SHA"] = 0xC018;
        $this->ciphers["TLS_ECDH_Anon_WITH_AES_256_CBC_SHA"] = 0xC019;
        $this->ciphers["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"] = 0xC01A;
        $this->ciphers["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"] = 0xC01B;
        $this->ciphers["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"] = 0xC01C;
        $this->ciphers["TLS_SRP_SHA_WITH_AES_128_CBC_SHA"] = 0xC01D;
        $this->ciphers["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"] = 0xC01E;
        $this->ciphers["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"] = 0xC01F;
        $this->ciphers["TLS_SRP_SHA_WITH_AES_256_CBC_SHA"] = 0xC020;
        $this->ciphers["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"] = 0xC021;
        $this->ciphers["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"] = 0xC022;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"] = 0xC023;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"] = 0xC024;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"]= 0xC025;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"]= 0xC026;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] = 0xC027;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"] = 0xC028;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"] = 0xC029;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"] = 0xC02A;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] = 0xC02B;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = 0xC02C;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"]= 0xC02D;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"]= 0xC02E;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] = 0xC02F;
        $this->ciphers["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = 0xC030;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"] = 0xC031;
        $this->ciphers["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"] = 0xC032;
        $this->ciphers["TLS_ECDHE_PSK_WITH_RC4_128_SHA"] = 0xC033;
        $this->ciphers["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"] = 0xC034;
        $this->ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"] = 0xC035;
        $this->ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"] = 0xC036;
        $this->ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"] = 0xC037;
        $this->ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"] = 0xC038;
        $this->ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA"] = 0xC039;
        $this->ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA256"] = 0xC03A;
        $this->ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA384"] = 0xC03B;
        $this->ciphers["TLS_RSA_WITH_ARIA_128_CBC_SHA256"] = 0xC03C;
        $this->ciphers["TLS_RSA_WITH_ARIA_256_CBC_SHA384"] = 0xC03D;
        $this->ciphers["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"] = 0xC03E;
        $this->ciphers["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"] = 0xC03F;
        $this->ciphers["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"] = 0xC040;
        $this->ciphers["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"] = 0xC041;
        $this->ciphers["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"] = 0xC042;
        $this->ciphers["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"] = 0xC043;
        $this->ciphers["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"] = 0xC044;
        $this->ciphers["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"] = 0xC045;
        $this->ciphers["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"] = 0xC046;
        $this->ciphers["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"] = 0xC047;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"] = 0xC048;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"] = 0xC049;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"] = 0xC04A;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"] = 0xC04B;
        $this->ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"]= 0xC04C;
        $this->ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"]= 0xC04D;
        $this->ciphers["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"] = 0xC04E;
        $this->ciphers["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"] = 0xC04F;
        $this->ciphers["TLS_RSA_WITH_ARIA_128_GCM_SHA256"] = 0xC050;
        $this->ciphers["TLS_RSA_WITH_ARIA_256_GCM_SHA384"] = 0xC051;
        $this->ciphers["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"] = 0xC052;
        $this->ciphers["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"] = 0xC053;
        $this->ciphers["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"] = 0xC054;
        $this->ciphers["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"] = 0xC055;
        $this->ciphers["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"] = 0xC056;
        $this->ciphers["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"] = 0xC057;
        $this->ciphers["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"] = 0xC058;
        $this->ciphers["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"] = 0xC059;
        $this->ciphers["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"] = 0xC05A;
        $this->ciphers["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"] = 0xC05B;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"] = 0xC05C;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"] = 0xC05D;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"] = 0xC05E;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"] = 0xC05F;
        $this->ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"] = 0xC060;
        $this->ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"] = 0xC061;
        $this->ciphers["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"] = 0xC062;
        $this->ciphers["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"] = 0xC063;
        $this->ciphers["TLS_PSK_WITH_ARIA_128_CBC_SHA256"] = 0xC064;
        $this->ciphers["TLS_PSK_WITH_ARIA_256_CBC_SHA384"] = 0xC065;
        $this->ciphers["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"] = 0xC066;
        $this->ciphers["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"] = 0xC067;
        $this->ciphers["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"] = 0xC068;
        $this->ciphers["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"] = 0xC069;
        $this->ciphers["TLS_PSK_WITH_ARIA_128_GCM_SHA256"] = 0xC06A;
        $this->ciphers["TLS_PSK_WITH_ARIA_256_GCM_SHA384"] = 0xC06B;
        $this->ciphers["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"] = 0xC06C;
        $this->ciphers["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"] = 0xC06D;
        $this->ciphers["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"] = 0xC06E;
        $this->ciphers["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"] = 0xC06F;
        $this->ciphers["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"] = 0xC070;
        $this->ciphers["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"] = 0xC071;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC072;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC073;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC074;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC075;
        $this->ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC076;
        $this->ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC077;
        $this->ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC078;
        $this->ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC079;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC07A;
        $this->ciphers["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC07B;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC07C;
        $this->ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC07D;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC07E;
        $this->ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC07F;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC080;
        $this->ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC081;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC082;
        $this->ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC083;
        $this->ciphers["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC084;
        $this->ciphers["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC085;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC086;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC087;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC088;
        $this->ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC089;
        $this->ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC08A;
        $this->ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC08B;
        $this->ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC08C;
        $this->ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC08D;
        $this->ciphers["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC08E;
        $this->ciphers["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC08F;
        $this->ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC090;
        $this->ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC091;
        $this->ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"] = 0xC092;
        $this->ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"] = 0xC093;
        $this->ciphers["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC094;
        $this->ciphers["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC095;
        $this->ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC096;
        $this->ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC097;
        $this->ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC098;
        $this->ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC099;
        $this->ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"] = 0xC09A;
        $this->ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"] = 0xC09B;
        $this->ciphers["TLS_RSA_WITH_AES_128_CCM"] = 0xC09C;
        $this->ciphers["TLS_RSA_WITH_AES_256_CCM"] = 0xC09D;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_128_CCM"] = 0xC09E;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_256_CCM"] = 0xC09F;
        $this->ciphers["TLS_RSA_WITH_AES_128_CCM_8"] = 0xC0A0;
        $this->ciphers["TLS_RSA_WITH_AES_256_CCM_8"] = 0xC0A1;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_128_CCM_8"] = 0xC0A2;
        $this->ciphers["TLS_DHE_RSA_WITH_AES_256_CCM_8"] = 0xC0A3;
        $this->ciphers["TLS_PSK_WITH_AES_128_CCM"] = 0xC0A4;
        $this->ciphers["TLS_PSK_WITH_AES_256_CCM"] = 0xC0A5;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_CCM"] = 0xC0A6;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_CCM"] = 0xC0A7;
        $this->ciphers["TLS_PSK_WITH_AES_128_CCM_8"] = 0xC0A8;
        $this->ciphers["TLS_PSK_WITH_AES_256_CCM_8"] = 0xC0A9;
        $this->ciphers["TLS_PSK_DHE_WITH_AES_128_CCM_8"] = 0xC0AA;
        $this->ciphers["TLS_PSK_DHE_WITH_AES_256_CCM_8"] = 0xC0AB;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"] = 0xC0AC;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM"] = 0xC0AD;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"] = 0xC0AE;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"] = 0xC0AF;
        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] = 0xCC14;
        $this->ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = 0xCC15;
        $this->ciphers["SSL_RSA_FIPS_WITH_DES_CBC_SHA"] = 0xFEFE;
        $this->ciphers["SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"] = 0xFEFF;
        $this->ciphers["SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"] = 0xFFE0;
        $this->ciphers["SSL_RSA_FIPS_WITH_DES_CBC_SHA"] = 0xFFE1;
        $this->ciphers["SSL_RSA_WITH_RC2_CBC_MD5"] = 0xFF80;
        $this->ciphers["SSL_RSA_WITH_IDEA_CBC_MD5"] = 0xFF81;
        $this->ciphers["SSL_RSA_WITH_DES_CBC_MD5"] = 0xFF82;
        $this->ciphers["SSL_RSA_WITH_3DES_EDE_CBC_MD5"] = 0xFF83;
        $this->ciphers["SSL_EN_RC2_128_CBC_WITH_MD5"] = 0xFF03;
        $this->ciphers["OP_PCL_TLS10_AES_128_CBC_SHA512"] = 0xFF85;
        $this->ciphers["SSL_CK_RC4_128_WITH_MD5"] = 0x10080;
        $this->ciphers["SSL2_DES_64_CBC_WITH_MD5"] = 0x060040;
        $this->ciphers["SSL_CK_DES_192_EDE3_CBC_WITH_MD5"] = 0x700c0;
        $this->ciphers["SSL2_RC4_128_WITH_MD5"] = 0x010080;
        $this->ciphers["TLS_EMPTY_RENEGOTIATION_INFO_SCSV"] = 0x00FF;



        $this->ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCA9;
        $this->ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCA8;
        $this->ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCAA;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"] = 0x00AD;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"] = 0x00AB;
        $this->ciphers["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCAE;
        $this->ciphers["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCAD;
        $this->ciphers["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCAC;
        $this->ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384"] = 0x00A9;
        $this->ciphers["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"] = 0xCCAB;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"] = 0x00AC;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"] = 0x00AA;
        $this->ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256"] = 0x00A8;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"] = 0x00B7;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"] = 0x00B3;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"] = 0x0095;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"] = 0x0091;
        $this->ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384"] = 0x00AF;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"] = 0x00B6;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"] = 0x00B2;
        $this->ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"] = 0x0094;
        $this->ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"] = 0x0090;
        $this->ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256"] = 0x00AE;
    }
    
    public function convertFromCloudflareFingerprints($input, $output) 
    {
        if(!file_exists($input)) {
            echo "file = '$input' doesn't exist\n";
            return;
        }
        
        $fp = fopen($input, "r");
        if(!$fp) {
            echo "fail to open file = '$input'\n";
            return;
        }
        
        $fw = fopen($output, "w+");
        if(!$fw) {
            echo "fail to open file = '$output'\n";
            return;
        }
        
        while(!feof($fp)) {
            $newfingerprint = "";
            $line = fgets($fp);
            
            #<browser_name>:<browser_version>:<os_platform>:<os_name>:<os_version>:<device_type>:<quirks>|<tls_version>:<cipher_suites>:<extension_names>:<curves>:<ec_point_fmts>:<http_headers>:<quirks>|<mitm_name>:<mitm_type>:<mitm_grade>
            preg_match("/([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*)\|([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*):([^:|]*)\|([^:|]*):([^:|]*):([^:|]*)/", $line, $matches);
        
            for($i = 1; $i < 9; $i ++) {
                if(isset($matches[$i])) {
                    $newfingerprint .= $matches[$i]."|";
                }
            }
            
            if(isset($matches[9])) {
                $explodedcipherlist = explode(',', $matches[9]);
                    
                foreach($explodedcipherlist as $cipherid) {
                    foreach($this->ciphers as $iananame => $hexid) {
                        if($hexid == $cipherid) {
                            $newfingerprint .= "$iananame:";
                        }
                    }
                }
            }
            
            $newfingerprint = substr($newfingerprint, 0, -1);
            $newfingerprint .= "|";
            
            for($i = 10; $i < 18; $i ++) {
                if(isset($matches[$i])) {
                    $newfingerprint .= $matches[$i]."|";
                }
            }
            
            $newfingerprint = substr($newfingerprint, 0, -1);
            
            fwrite($fw, "$newfingerprint\n");
        }

        fclose($fp);
        fclose($fw);
    }
}

