#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "haval.h"

#define TEST_RESULT(n, v) static const char* const result##n = v

#define TEST_RESULTS(r1, r2, r3, r4, r5, r6, r7) \
    TEST_RESULT(1, r1); \
    TEST_RESULT(2, r2); \
    TEST_RESULT(3, r3); \
    TEST_RESULT(4, r4); \
    TEST_RESULT(5, r5); \
    TEST_RESULT(6, r6); \
    TEST_RESULT(7, r7);

#if PASS == 3 && FPTLEN == 128
TEST_RESULTS(
        "C68F39913F901F3DDF44C707357A7D70",
        "0CD40739683E15F01CA5DBCEEF4059F1",
        "DC1F3C893D17CC4EDD9AE94AF76A0AF0",
        "D4BE2164EF387D9F4D46EA8EFB180CF5",
        "DC502247FB3EB8376109EDA32D361D82",
        "DE5EB3F7D9EB08FAE7A07D68E3047EC6",
        "78DF3722C78E040D22A63355500803F8")
#elif PASS == 3 && FPTLEN == 160
TEST_RESULTS(
        "D353C3AE22A25401D257643836D7231A9A95F953",
        "4DA08F514A7275DBC4CECE4A347385983983A830",
        "8822BC6F3E694E73798920C77CE3245120DD8214",
        "BE68981EB3EBD3F6748B081EE5D4E1818F9BA86C",
        "EBA9FA6050F24C07C29D1834A60900EA4E32E61B",
        "97DC988D97CAAE757BE7523C4E8D4EA63007A4B9",
        "A3A5D4AE1BADFB2435ECC4CAB92B012DB24874C1")
#elif PASS == 3 && FPTLEN == 192
TEST_RESULTS(
        "E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E",
        "B359C8835647F5697472431C142731FF6E2CDDCACC4F6E08",
        "8DA26DDAB4317B392B22B638998FE65B0FBE4610D345CF89",
        "DE561F6D818A760D65BDD2823ABE79CDD97E6CFA4021B0C8",
        "A25E1456E6863E7D7C74017BB3E098E086AD4BE0580D7056",
        "DEF6653091E3005B43A61681014A066CD189009D00856EE7",
        "8E7A13CB0D4D6FEE34976E81392DC71E747B9B49638F7A17")
#elif PASS == 3 && FPTLEN == 224
TEST_RESULTS(
        "C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D",
        "731814BA5605C59B673E4CAAE4AD28EEB515B3ABC2B198336794E17B",
        "AD33E0596C575D7175E9F72361CA767C89E46E2609D88E719EE69AAA",
        "EE345C97A58190BF0F38BF7CE890231AA5FCF9862BF8E7BEBBF76789",
        "06AE38EBC43DB58BD6B1D477C7B4E01B85A1E7B19B0BD088E33B58D1",
        "939F7ED7801C1CE4B32BC74A4056EEE6081C999ED246907ADBA880A7",
        "C5C22E1A463BDD61823B68B0BD04E75ED41189D60F91628354D88913")
#elif PASS == 3 && FPTLEN == 256
TEST_RESULTS(
        "4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17",
        "47C838FBB4081D9525A0FF9B1E2C05A98F625714E72DB289010374E27DB021D8",
        "91850C6487C9829E791FC5B58E98E372F3063256BB7D313A93F1F83B426AEDCC",
        "63238D99C02BE18C3C5DB7CCE8432F51329012C228CCC17EF048A5D0FD22D4AE",
        "72FAD4BDE1DA8C8332FB60561A780E7F504F21547B98686824FC33FC796AFA76",
        "899397D96489281E9E76D5E65ABAB751F312E06C06C07C9C1D42ABD31BB6A404",
        "DC2E548796DDA1BD4D575B2249BFBC59BE2902B1DA045F88891DEB43369D0CFD")
#elif PASS == 4 && FPTLEN == 128
TEST_RESULTS(
        "EE6BBF4D6A46A679B3A856C88538BB98",
        "5CD07F03330C3B5020B29BA75911E17D",
        "958195D3DAC591030EAA0292A37A0CF2",
        "2215D3702A80025C858062C53D76CBE5",
        "B2A73B99775FFB17CD8781B85EC66221",
        "CAD57C0563BDA208D66BB89EB922E2A2",
        "10A3B1BAA6C34BDD72CA03D9855BEE19")
#elif PASS == 4 && FPTLEN == 160
TEST_RESULTS(
        "1D33AAE1BE4146DBAACA0B6E70D7A11F10801525",
        "E0A5BE29627332034D4DD8A910A1A0E6FE04084D",
        "221BA4DD206172F12C2EBA3295FDE08D25B2F982",
        "E387C743D14DF304CE5C7A552F4C19CA9B8E741C",
        "1C7884AF86D11AC120FE5DF75CEE792D2DFA48EF",
        "148334AAD24B658BDC946C521CDD2B1256608C7B",
        "2983B32D6B0B76498BD6D94966BBF1A16D87DA13")
#elif PASS == 4 && FPTLEN == 192
TEST_RESULTS(
        "4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA",
        "856C19F86214EA9A8A2F0C4B758B973CCE72A2D8FF55505C",
        "0C1396D7772689C46773F3DAACA4EFA982ADBFB2F1467EEA",
        "C3A5420BB9D7D82A168F6624E954AAA9CDC69FB0F67D785E",
        "2E2E581D725E799FDA1948C75E85A28CFE1CF0C6324A1ADA",
        "E5C9F81AE0B31FC8780FC37CB63BB4EC96496F79A9B58344",
        "7714262AD7D5E7ACE5F38E2F5AA16DBD61788E0F950C4DB8")
#elif PASS == 4 && FPTLEN == 224
TEST_RESULTS(
        "3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E",
        "742F1DBEEAF17F74960558B44F08AA98BDC7D967E6C0AB8F799B3AC1",
        "85538FFC06F3B1C693C792C49175639666F1DDE227DA8BD000C1E6B4",
        "BEBD7816F09BAEECF8903B1B9BC672D9FA428E462BA699F814841529",
        "A0AC696CDB2030FA67F6CC1D14613B1962A7B69B4378A9A1B9738796",
        "3E63C95727E0CD85D42034191314401E42AB9063A94772647E3E8E0F",
        "2491A1689A35DFE63C4B4F6810E676133F44412C5ADC959478DDB9F8")
#elif PASS == 4 && FPTLEN == 256
TEST_RESULTS(
        "C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B",
        "E686D2394A49B44D306ECE295CF9021553221DB132B36CC0FF5B593D39295899",
        "E20643CFA66F5BE2145D13ED09C2FF622B3F0DA426A693FA3B3E529CA89E0D3C",
        "ACE5D6E5B155F7C9159F6280327B07CBD4FF54143DC333F0582E9BCEB895C05D",
        "124F6EB645DC407637F8F719CC31250089C89903BF1DB8FAC21EA4614DF4E99A",
        "46A3A1DFE867EDE652425CCD7FE8006537EAD26372251686BEA286DA152DC35A",
        "E8162C7F8A83FF15549CD84B991333A5B3851A0FC600B513B25B69EC17B58AFC")
#elif PASS == 5 && FPTLEN == 128
TEST_RESULTS(
        "184B8482A0C050DCA54B59C7F05BF5DD",
        "F23FBE704BE8494BFA7A7FB4F8AB09E5",
        "C97990F4FCC8FBA76AF935C405995355",
        "466FDCD81C3477CAC6A31FFA1C999CA8",
        "0EFFF71D7D14344CBA1F4B25F924A693",
        "4B27D04DDB516BDCDFEB96EB8C7C8E90",
        "7BCF71603BA4B06DA1807B3553A32A9D")
#elif PASS == 5 && FPTLEN == 160
TEST_RESULTS(
        "255158CFC1EED1A7BE7C55DDD64D9790415B933B",
        "F5147DF7ABC5E3C81B031268927C2B5761B5A2B5",
        "7730CA184CEA2272E88571A7D533E035F33B1096",
        "41CC7C1267E88CEF0BB93697D0B6C8AFE59061E6",
        "917836A9D27EED42D406F6002E7D11A0F87C404C",
        "6DDBDE98EA1C4F8C7F360FB9163C7C952680AA70",
        "6B20574F400699BE71CBFDBD9FEE4BB922FEDF8C")
#elif PASS == 5 && FPTLEN == 192
TEST_RESULTS(
        "4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85",
        "5FFA3B3548A6E2CFC06B7908CEB5263595DF67CF9C4B9341",
        "794A896D1780B76E2767CC4011BAD8885D5CE6BD835A71B8",
        "A0B635746E6CFFFFD4B4A503620FEF1040C6C0C5C326476E",
        "85F1F1C0ECA04330CF2DE5C8C83CF85A611B696F793284DE",
        "D651C8AC45C9050810D9FD64FC919909900C4664BE0336D0",
        "4F656849D05EFC42EAF3C603DB4435DDCED1985297070A47")
#elif PASS == 5 && FPTLEN == 224
TEST_RESULTS(
        "4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E",
        "67B3CB8D4068E3641FA4F156E03B52978B421947328BFB9168C7655D",
        "9D7AE77B8C5C8C1C0BA854EBE3B2673C4163CFD304AD7CD527CE0C82",
        "59836D19269135BC815F37B2AEB15F894B5435F2C698D57716760F2B",
        "1B360ACFF7806502B5D40C71D237CC0C40343D2000AE2F65CF487C94",
        "180AED7F988266016719F60148BA2C9B4F5EC3B9758960FC735DF274",
        "76A6D848358C9883BB28CA358A34558CD13FD9EC5DFDF7DBBCBF629B")
#elif PASS == 5 && FPTLEN == 256
TEST_RESULTS(
        "BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330",
        "DE8FD5EE72A5E4265AF0A756F4E1A1F65C9B2B2F47CF17ECF0D1B88679A3E22F",
        "153D2C81CD3C24249AB7CD476934287AF845AF37F53F51F5C7E2BE99BA28443F",
        "357E2032774ABBF5F04D5F1DEC665112EA03B23E6E00425D0DF75EA155813126",
        "C9C7D8AFA159FD9E965CB83FF5EE6F58AEDA352C0EFF005548153A61551C38EE",
        "B45CB6E62F2B1320E4F8F1B0B273D45ADD47C321FD23999DCF403AC37636D963",
        "AABF0B45AC4A4E84268F50ABCC3EF3806BCC9860EA6A92425F537C46A957963A")
#endif

static int exit_code = 0;

static void verify_result(const char* data, const unsigned char* got, const char* expected, int is_file)
{
    static const char* const hex = "0123456789ABCDEF";

    int i, result = 0;

    printf("HAVAL(%s%s%s) = ", is_file ? "File " : "\"", data, is_file ? "" : "\"");

    for (i = 0; i < (FPTLEN >> 3); ++i) {
        const char c1 = hex[got[i] >> 4];
        const char c2 = hex[got[i] & 0x0F];

        printf("%c%c", c1, c2);

        if (c1 != expected[i * 2] || c2 != expected[i * 2 + 1]) {
            result = 1;
        }
    }

    if (result) {
        printf(" != %s", expected);
        exit_code = 1;
    }

    printf("\n");
}

/* hash a set of certification data and print the results.  */
int main()
{
    char* str;
    unsigned char fingerprint[FPTLEN >> 3];

    printf("HAVAL certification data (PASS=%d, FPTLEN=%d):\n", PASS, FPTLEN);

    str = "";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result1, 0);

    str = "a";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result2, 0);

    str = "HAVAL";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result3, 0);

    str = "0123456789";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result4, 0);

    str = "abcdefghijklmnopqrstuvwxyz";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result5, 0);

    str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    haval_string(str, fingerprint);
    verify_result(str, fingerprint, result6, 0);

    str = "pi.frac";
    if (haval_file(str, fingerprint)) {
        printf("%s cannot be opened! Skipping test...\n", str);
    } else {
        verify_result(str, fingerprint, result7, 1);
    }

    return exit_code;
}