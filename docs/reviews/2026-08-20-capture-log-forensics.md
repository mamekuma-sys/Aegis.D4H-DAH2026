# 2026-08-20 본선 Capture·Log 포렌식 및 P0 개선

## 1. 한 줄 결론

P1–P3의 PCAP 104개와 로그 21개에서 관측된 공격 형태는 현재 방어 정책 재생에서 전부 차단되고 정상 요청의 예상 밖 DROP은 없었으며, 공격자 감사·종료와 방어자 상태 관측성을 보강한 뒤 공식 Linux Broker의 관측된 ACCEPT 경로가 두 차례 p99/max 552.070 us·530.152 us로 300 ms 안에 동작하고 Router 재시작 후 재연결됨을 확인했다. 다만 P4/L4 증거와 실제 DROP 경로, 공식 스켈레톤 서비스 결함 때문에 flag·SLA 효과는 여전히 미확인이다.

## 2. 범위와 제한

- 사용 근거: 현재 `capture/`, `log/`, 공식 본선 운영세칙, 공식 본선 당일 안내, 공식 `deploy/docs/agent-guide.md`, 공식 스켈레톤의 관측 가능한 구조, 현재 HEAD 코드·테스트.
- 사용하지 않은 근거: 예선 보고서, 예선 소스 코드.
- 분석 범위: 파일명 라벨 기준 P1/R1부터 P3/R18까지. P4/L4 capture 또는 log는 발견되지 않았다.
- 출처 충돌: 최신 본선 당일 안내는 4 Phase·14 Round(P1 2, P2 4, P3 4, P4 4)를 명시하지만 증거 파일명은 P1/R1–R6, P2/R7–R12, P3/R13–R18이다. 공식 안내를 우선하므로 파일명의 Phase/Round는 실제 본선 일정 확정값이 아니라 `추정 라벨`로만 사용한다.
- 공식 운영세칙 제6조는 10분 간격의 PCAP·공방 로그 제공을 명시해 파일 생성 주기와는 일치한다. 그러나 Round 번호 충돌을 해소하지는 못한다.
- 도구: 저장소의 `agents/defender/tools/replay_pcaps.py` 및 Python 표준 라이브러리 기반 읽기 전용 메타데이터 분석.
- `tshark`, `capinfos`, `tcpdump`는 설치되어 있지 않아 exact TCP expert analysis는 차단됐다. 임의 설치하지 않았다.
- Linux 검증: 공식 외부 스켈레톤을 수정하지 않고 Docker Linux/amd64에서 Team 1 이미지를 빌드·실행했다. 라이브 결과는 원본 본선 capture/log와 구분해 `LIVE-*` Evidence로 기록한다.
- 원본의 주소, flag, token, cookie, session, 요청 body는 출력하거나 문서화하지 않았다.

## 3. Evidence inventory

Evidence ID는 이 문서 안에서만 쓰는 안정적인 참조다. 파일명은 저장소 상대경로이고 개인 절대경로는 기록하지 않는다.

### 3.1 PCAP 104개

<!-- PCAP_INVENTORY_START -->
| Evidence ID | 유형 | 파일명 | 크기 | SHA-256 | 시간 범위 (UTC) | 추정 Phase/Round | 파싱 상태 |
|---|---|---|---:|---|---|---|---|
| PCAP-001 | pcap | `capture/TEAM1-P1-R1-l1-20260815010006.pcap` | 791,562 | `11b0a5020a1fd127475180d852fc0eec950a845aac4cf36d82c097a90000a1bb` | `2026-08-15T01:00:14.748452Z` ~ `2026-08-15T01:10:05.356767Z` | P1/R1/L1 | OK (7,295 packets) |
| PCAP-002 | pcap | `capture/TEAM1-P1-R1-l1-20260815011006.pcap` | 815,652 | `c65db39c07a69fb6da3e82120d54359c25bf4f8194d22a8a3f958a3ed4846de7` | `2026-08-15T01:10:06.316514Z` ~ `2026-08-15T01:20:01.048217Z` | P1/R1/L1 | OK (7,526 packets) |
| PCAP-003 | pcap | `capture/TEAM1-P1-R2-l1-20260815014004.pcap` | 688,455 | `b2d537368f56bb70060aa80b0c9ab7f2b04c5ca9b41a190907a1da78fa086aef` | `2026-08-15T01:40:07.990218Z` ~ `2026-08-15T01:50:02.768436Z` | P1/R2/L1 | OK (6,297 packets) |
| PCAP-004 | pcap | `capture/TEAM1-P1-R2-l1-20260815015007.pcap` | 645,184 | `a859ef5367646cad031bbd85ffb7164fde27729ee0c6818b42a9cbef60c9f9a5` | `2026-08-15T01:50:07.057488Z` ~ `2026-08-15T02:00:05.063788Z` | P1/R2/L1 | OK (5,930 packets) |
| PCAP-005 | pcap | `capture/TEAM1-P1-R2-l1-20260815020007.pcap` | 6,809 | `c17f00f6eeb9ac2f8e7541c5f3aced57849cb4a206725bb284806401323bb944` | `2026-08-15T02:00:06.905454Z` ~ `2026-08-15T02:00:10.317916Z` | P1/R2/L1 | OK (59 packets) |
| PCAP-006 | pcap | `capture/TEAM1-P1-R3-l1-20260815022004.pcap` | 497,166 | `10623567bb57acd4682273eecc4054b3b0588f7a1db8276880d6dcccbb4ecbf6` | `2026-08-15T02:20:07.709238Z` ~ `2026-08-15T02:30:03.787849Z` | P1/R3/L1 | OK (4,592 packets) |
| PCAP-007 | pcap | `capture/TEAM1-P1-R3-l1-20260815023004.pcap` | 427,013 | `d4a33e59523f459b992553bad60098bfa267560ab6b10b801d772c0b89e68a64` | `2026-08-15T02:30:04.748252Z` ~ `2026-08-15T02:40:01.048210Z` | P1/R3/L1 | OK (3,968 packets) |
| PCAP-008 | pcap | `capture/TEAM1-P1-R3-l1-20260815024005.pcap` | 9,999 | `6b21df627fba4a384a1157204f5fadf98c666adc95de2c3271ba905e503a4299` | `2026-08-15T02:40:05.169262Z` ~ `2026-08-15T02:40:11.414255Z` | P1/R3/L1 | OK (92 packets) |
| PCAP-009 | pcap | `capture/TEAM1-P1-R4-l1-20260815030005.pcap` | 392,954 | `b81e178fc7e0b426e9e54243b6439611fa82518515c5dde9ece921d9182795f3` | `2026-08-15T03:00:08.493162Z` ~ `2026-08-15T03:10:01.048203Z` | P1/R4/L1 | OK (3,660 packets) |
| PCAP-010 | pcap | `capture/TEAM1-P1-R4-l1-20260815031008.pcap` | 310,374 | `982f05b8ff40a28f2c0123d8a32db66afd1a2a9c3d21d4fef33aff01c8401524` | `2026-08-15T03:10:08.039035Z` ~ `2026-08-15T03:20:01.048263Z` | P1/R4/L1 | OK (2,897 packets) |
| PCAP-011 | pcap | `capture/TEAM1-P1-R5-l1-20260815034005.pcap` | 350,823 | `f0c231d12d3b01edbd6df29370dd24f75782d120c978a596744dd9925ba9712a` | `2026-08-15T03:40:08.506576Z` ~ `2026-08-15T03:50:01.048227Z` | P1/R5/L1 | OK (3,227 packets) |
| PCAP-012 | pcap | `capture/TEAM1-P1-R5-l1-20260815035005.pcap` | 295,412 | `4ed5ee539eb14440131df0a14992670bbe6cbf169809caa31ecf946528f6fe44` | `2026-08-15T03:50:04.724143Z` ~ `2026-08-15T04:00:01.048256Z` | P1/R5/L1 | OK (2,735 packets) |
| PCAP-013 | pcap | `capture/TEAM1-P1-R6-l1-20260815042005.pcap` | 6,321,601 | `77df7dd828c142c4275c485d685a69931579b025223dcb546a3b47114524ea99` | `2026-08-15T04:20:08.614372Z` ~ `2026-08-15T04:30:03.345416Z` | P1/R6/L1 | OK (52,702 packets) |
| PCAP-014 | pcap | `capture/TEAM1-P1-R6-l1-20260815043005.pcap` | 5,897,262 | `1c01ba6336d146ec580eb860ffb6a1a2c52567328457d7ae9250235c634e537f` | `2026-08-15T04:30:04.805196Z` ~ `2026-08-15T04:40:04.728284Z` | P1/R6/L1 | OK (49,040 packets) |
| PCAP-015 | pcap | `capture/TEAM1-P1-R6-l1-20260815044005.pcap` | 27,203 | `4c4a9f9c8c18270cb41e89d4b468605971dc2e13fee7a6d4ded8f1f5d917cf3f` | `2026-08-15T04:40:04.835064Z` ~ `2026-08-15T04:40:13.418919Z` | P1/R6/L1 | OK (243 packets) |
| PCAP-016 | pcap | `capture/TEAM1-P2-R10-l1-20260815070006.pcap` | 987,740 | `555944b6cdae9e7745d27b689e838acfdd5c8208b890d158671d5409d090d811` | `2026-08-15T07:00:10.210061Z` ~ `2026-08-15T07:10:01.783545Z` | P2/R10/L1 | OK (8,212 packets) |
| PCAP-017 | pcap | `capture/TEAM1-P2-R10-l1-20260815071006.pcap` | 745,081 | `43f1ca7d289553a95f561314c3fc4618df536b176d4ff24513671f968b0a8bd0` | `2026-08-15T07:10:06.520270Z` ~ `2026-08-15T07:20:05.900417Z` | P2/R10/L1 | OK (5,879 packets) |
| PCAP-018 | pcap | `capture/TEAM1-P2-R10-l1-20260815072006.pcap` | 10,154 | `6d9c7187aa2ffeb0e5dc093e45c5fcf8fb17c52be70adc2339b24fc2abd1bc80` | `2026-08-15T07:20:05.935528Z` ~ `2026-08-15T07:20:14.125531Z` | P2/R10/L1 | OK (90 packets) |
| PCAP-019 | pcap | `capture/TEAM1-P2-R10-l2-20260815070006.pcap` | 1,140,007 | `1dcd28704afe863e872f7046798f4115c86f566a30cad81c8e56223618385db8` | `2026-08-15T07:00:10.309641Z` ~ `2026-08-15T07:10:03.032281Z` | P2/R10/L2 | OK (8,941 packets) |
| PCAP-020 | pcap | `capture/TEAM1-P2-R10-l2-20260815071006.pcap` | 1,608,992 | `bc6168e7c88f4d8daadaa479781b6cea7b2235bc6b7390b5a9ebc4da190f6326` | `2026-08-15T07:10:06.528780Z` ~ `2026-08-15T07:20:05.477943Z` | P2/R10/L2 | OK (12,967 packets) |
| PCAP-021 | pcap | `capture/TEAM1-P2-R10-l2-20260815072006.pcap` | 23,061 | `eb2e60d59092a2a92627b6df1bfe1aab81013472e456fd4e3055b9ce7013c680` | `2026-08-15T07:20:05.929028Z` ~ `2026-08-15T07:20:14.158295Z` | P2/R10/L2 | OK (181 packets) |
| PCAP-022 | pcap | `capture/TEAM1-P2-R11-l1-20260815074005.pcap` | 824,111 | `b33ea3a21991f5618fe772c1fd5054b21d402895c66c9a9017681e9d2790f6a0` | `2026-08-15T07:40:09.283877Z` ~ `2026-08-15T07:50:01.048240Z` | P2/R11/L1 | OK (6,811 packets) |
| PCAP-023 | pcap | `capture/TEAM1-P2-R11-l1-20260815075007.pcap` | 657,834 | `94c94d8b90dc9f260d5e323e616589709aefa7ff8c93d4e226f6ac20d9bf446f` | `2026-08-15T07:50:07.057657Z` ~ `2026-08-15T08:00:01.731999Z` | P2/R11/L1 | OK (4,996 packets) |
| PCAP-024 | pcap | `capture/TEAM1-P2-R11-l1-20260815080008.pcap` | 3,024 | `de700c95782ae6c45c3260a92ad7c2c64a1d707b8a9b1d2a396d823bd4b3bc3c` | `2026-08-15T08:00:07.190390Z` ~ `2026-08-15T08:00:14.217098Z` | P2/R11/L1 | OK (27 packets) |
| PCAP-025 | pcap | `capture/TEAM1-P2-R11-l2-20260815074005.pcap` | 992,412 | `9666c2a5b2fe0a12e9214d7b3e5c334d7209e872eee0fcaa06692a6f8877db52` | `2026-08-15T07:40:09.491127Z` ~ `2026-08-15T07:50:03.032267Z` | P2/R11/L2 | OK (7,819 packets) |
| PCAP-026 | pcap | `capture/TEAM1-P2-R11-l2-20260815075008.pcap` | 1,597,014 | `540ed173b6f415acbef74bb1ce2805d3b0444b29ccafdf55539f3a5a90752f2f` | `2026-08-15T07:50:07.799552Z` ~ `2026-08-15T08:00:03.032217Z` | P2/R11/L2 | OK (12,805 packets) |
| PCAP-027 | pcap | `capture/TEAM1-P2-R11-l2-20260815080008.pcap` | 4,697 | `cf6170b8a6f2b237982234b21881921f96069f68de5c23f35eeb5f541ab82d2b` | `2026-08-15T08:00:07.195248Z` ~ `2026-08-15T08:00:14.217218Z` | P2/R11/L2 | OK (43 packets) |
| PCAP-028 | pcap | `capture/TEAM1-P2-R12-l1-20260815082002.pcap` | 628,859 | `168ca7f222b65dec2efd29f828091cfd75e87c93f7f0c04e8a78129209d1fcf6` | `2026-08-15T08:20:05.378848Z` ~ `2026-08-15T08:30:01.048200Z` | P2/R12/L1 | OK (5,126 packets) |
| PCAP-029 | pcap | `capture/TEAM1-P2-R12-l1-20260815083002.pcap` | 343,830 | `590037569f52878f28348e06f3abf525f850d33f13caa04cd8191e4156a6bf68` | `2026-08-15T08:30:01.661006Z` ~ `2026-08-15T08:40:01.048290Z` | P2/R12/L1 | OK (2,754 packets) |
| PCAP-030 | pcap | `capture/TEAM1-P2-R12-l1-20260815084011.pcap` | 3,774 | `17f3c21997721d98a1b85c88ac0202b4706b8dc9df183195700e16c6d2df1655` | `2026-08-15T08:40:10.760735Z` ~ `2026-08-15T08:40:14.190271Z` | P2/R12/L1 | OK (36 packets) |
| PCAP-031 | pcap | `capture/TEAM1-P2-R12-l2-20260815082002.pcap` | 885,471 | `02d2ec8707a92f0c68235567e7ccc772c9c72a9515170b19c60b157b30ce4368` | `2026-08-15T08:20:05.628598Z` ~ `2026-08-15T08:30:01.169179Z` | P2/R12/L2 | OK (6,869 packets) |
| PCAP-032 | pcap | `capture/TEAM1-P2-R12-l2-20260815083002.pcap` | 1,217,012 | `47b78ec1d8eb91907de746728e484b8ca94e5ab156c8db2f760d8522375d94f0` | `2026-08-15T08:30:02.038495Z` ~ `2026-08-15T08:40:01.336401Z` | P2/R12/L2 | OK (10,121 packets) |
| PCAP-033 | pcap | `capture/TEAM1-P2-R12-l2-20260815084002.pcap` | 23,460 | `519211300dabc45bbb8241d8095bcf2778b0f389693d041ab1a54cb935411901` | `2026-08-15T08:40:02.019861Z` ~ `2026-08-15T08:40:14.229264Z` | P2/R12/L2 | OK (177 packets) |
| PCAP-034 | pcap | `capture/TEAM1-P2-R7-l1-20260815050006.pcap` | 5,923,345 | `3d56812430b1742a1558b2f510657ff788199f0d79dd6bb6afa2625e8789d906` | `2026-08-15T05:00:10.458170Z` ~ `2026-08-15T05:10:05.380518Z` | P2/R7/L1 | OK (48,351 packets) |
| PCAP-035 | pcap | `capture/TEAM1-P2-R7-l1-20260815051006.pcap` | 6,135,926 | `338b94a905f94b2bc5d150064d091b9c6bbb4f1aa6250f932056cc7174f5741c` | `2026-08-15T05:10:05.401027Z` ~ `2026-08-15T05:20:05.456599Z` | P2/R7/L1 | OK (50,228 packets) |
| PCAP-036 | pcap | `capture/TEAM1-P2-R7-l1-20260815052006.pcap` | 210,726 | `50055767593ada686fab9fc819adf9a28a36665df3206ec377a13349fd76ee7c` | `2026-08-15T05:20:05.485390Z` ~ `2026-08-15T05:20:14.313767Z` | P2/R7/L1 | OK (1,775 packets) |
| PCAP-037 | pcap | `capture/TEAM1-P2-R7-l2-20260815050006.pcap` | 649,967 | `bf65df8f214e9e6a25deb327ce57197478cf36cbe83541b3f6a913b471b45c60` | `2026-08-15T05:00:10.748328Z` ~ `2026-08-15T05:10:03.465907Z` | P2/R7/L2 | OK (5,012 packets) |
| PCAP-038 | pcap | `capture/TEAM1-P2-R7-l2-20260815051006.pcap` | 526,959 | `bac16c8a608e8823cedc39db0aebcf15c97e85a5c85d5ab7484e697ed90c64d6` | `2026-08-15T05:10:05.468812Z` ~ `2026-08-15T05:20:03.096188Z` | P2/R7/L2 | OK (4,228 packets) |
| PCAP-039 | pcap | `capture/TEAM1-P2-R7-l2-20260815052014.pcap` | 188 | `0b55304cf17be7ae27bc9369597b96b69868db4db91fe365756e4ade338ee2e1` | `2026-08-15T05:20:14.307316Z` ~ `2026-08-15T05:20:14.307918Z` | P2/R7/L2 | OK (2 packets) |
| PCAP-040 | pcap | `capture/TEAM1-P2-R8-l1-20260815054006.pcap` | 1,348,811 | `4ffef28916aa1f75f56ebf9be600972234f8a32f61c43ba4d7e8dd41715dc04c` | `2026-08-15T05:40:09.950420Z` ~ `2026-08-15T05:50:05.114598Z` | P2/R8/L1 | OK (11,685 packets) |
| PCAP-041 | pcap | `capture/TEAM1-P2-R8-l1-20260815055008.pcap` | 1,310,511 | `1f229c69886377074d5cfdb9264b0ed4efff9e8b23a1de5498a560e945da9e08` | `2026-08-15T05:50:08.057520Z` ~ `2026-08-15T06:00:07.115022Z` | P2/R8/L1 | OK (10,934 packets) |
| PCAP-042 | pcap | `capture/TEAM1-P2-R8-l1-20260815060011.pcap` | 3,692 | `36d79d6020ab470bd60c2bdc8fbfca81d2e93e1cd68762ffb58351b4461d929c` | `2026-08-15T06:00:11.095830Z` ~ `2026-08-15T06:00:14.756840Z` | P2/R8/L1 | OK (35 packets) |
| PCAP-043 | pcap | `capture/TEAM1-P2-R8-l2-20260815054006.pcap` | 2,111,449 | `5d8d2d9bd144524ca86b4693bb57c8951764b2dc92d644eee1d51b0841ebbeab` | `2026-08-15T05:40:10.064787Z` ~ `2026-08-15T05:50:03.096226Z` | P2/R8/L2 | OK (18,201 packets) |
| PCAP-044 | pcap | `capture/TEAM1-P2-R8-l2-20260815055006.pcap` | 1,078,677 | `50609b9636fe707be4ce5c1deb214ce1889c94c886bbd3d0dcfd0c90a27e9b69` | `2026-08-15T05:50:05.801508Z` ~ `2026-08-15T06:00:03.032242Z` | P2/R8/L2 | OK (9,221 packets) |
| PCAP-045 | pcap | `capture/TEAM1-P2-R8-l2-20260815060007.pcap` | 19,290 | `11af5e245b60df961de8e6410a6fffdd7f8cf7d09a4441dc349ceedcdab45098` | `2026-08-15T06:00:06.868248Z` ~ `2026-08-15T06:00:14.748868Z` | P2/R8/L2 | OK (169 packets) |
| PCAP-046 | pcap | `capture/TEAM1-P2-R9-l1-20260815062006.pcap` | 876,865 | `a72db431f1f16254bc85fef66dc2dd9cf8a857e71e35aca20dd567078fb88a7c` | `2026-08-15T06:20:09.546834Z` ~ `2026-08-15T06:30:01.048213Z` | P2/R9/L1 | OK (7,214 packets) |
| PCAP-047 | pcap | `capture/TEAM1-P2-R9-l1-20260815063008.pcap` | 657,048 | `6c6a88a13b1f949b31491138d21bd4767f74015b9f406972ae845e29a22eaa43` | `2026-08-15T06:30:08.048295Z` ~ `2026-08-15T06:40:01.048221Z` | P2/R9/L1 | OK (5,061 packets) |
| PCAP-048 | pcap | `capture/TEAM1-P2-R9-l1-20260815064014.pcap` | 188 | `d2989c15fd2e3a340277a096a228bf8af83228cfe3ea4347393b7c6c8e5e0c8e` | `2026-08-15T06:40:13.702768Z` ~ `2026-08-15T06:40:13.703824Z` | P2/R9/L1 | OK (2 packets) |
| PCAP-049 | pcap | `capture/TEAM1-P2-R9-l2-20260815062006.pcap` | 785,966 | `5070e8e73c1048e91da7ac58ae33c454ff4b7aa950a47091a4077e4888d08f63` | `2026-08-15T06:20:09.566769Z` ~ `2026-08-15T06:30:03.032255Z` | P2/R9/L2 | OK (6,460 packets) |
| PCAP-050 | pcap | `capture/TEAM1-P2-R9-l2-20260815063010.pcap` | 1,392,388 | `aea87e5bf3c7208dcdbec532cc662fb25c4dde6d004ee65f19508d948dae4077` | `2026-08-15T06:30:10.049819Z` ~ `2026-08-15T06:40:03.032277Z` | P2/R9/L2 | OK (11,326 packets) |
| PCAP-051 | pcap | `capture/TEAM1-P2-R9-l2-20260815064014.pcap` | 188 | `ab1dfb336ef2f7ec87be8bfe4fa29b46e0a78d70da60284757e0dfae4824dd67` | `2026-08-15T06:40:13.706168Z` ~ `2026-08-15T06:40:13.706732Z` | P2/R9/L2 | OK (2 packets) |
| PCAP-052 | pcap | `capture/TEAM1-P3-R13-l1-20260815090002.pcap` | 565,684 | `2ddc00657922e6d06c62cd3df99069777fa29948999228d08ef6a2c2730b7fb0` | `2026-08-15T09:00:08.185931Z` ~ `2026-08-15T09:10:01.048182Z` | P3/R13/L1 | OK (4,492 packets) |
| PCAP-053 | pcap | `capture/TEAM1-P3-R13-l1-20260815091008.pcap` | 279,388 | `391cf90ff0a16f758e7ce8cc1c53ffbcf5376b90ce8db2e11a4d82aad74b8d78` | `2026-08-15T09:10:08.056527Z` ~ `2026-08-15T09:20:06.418794Z` | P3/R13/L1 | OK (2,184 packets) |
| PCAP-054 | pcap | `capture/TEAM1-P3-R13-l1-20260815092016.pcap` | 3,762 | `6efb169e8ebf7f96880b662b06d95f3b8493f18469373c573ffa36f35ab10c12` | `2026-08-15T09:20:15.330091Z` ~ `2026-08-15T09:20:15.569121Z` | P3/R13/L1 | OK (36 packets) |
| PCAP-055 | pcap | `capture/TEAM1-P3-R13-l2-20260815090002.pcap` | 725,081 | `8e7ba6c562dcb60b684b273137763c81b9b35bdf01c1f8fc4af7e48ab26c391a` | `2026-08-15T09:00:08.414617Z` ~ `2026-08-15T09:09:22.755636Z` | P3/R13/L2 | OK (5,503 packets) |
| PCAP-056 | pcap | `capture/TEAM1-P3-R13-l2-20260815091002.pcap` | 142,640 | `53f1d9be502a190af7478a920d87680585a8c166b51ac6abb45793ca3f52947d` | `2026-08-15T09:10:02.027785Z` ~ `2026-08-15T09:19:14.012292Z` | P3/R13/L2 | OK (1,295 packets) |
| PCAP-057 | pcap | `capture/TEAM1-P3-R13-l2-20260815092002.pcap` | 3,686 | `7685abd4c622271c9a0642cfa20c030e36238c8306be36c02eb311b4412142d2` | `2026-08-15T09:20:02.049345Z` ~ `2026-08-15T09:20:13.031916Z` | P3/R13/L2 | OK (35 packets) |
| PCAP-058 | pcap | `capture/TEAM1-P3-R13-l3-20260815090002.pcap` | 1,052,958 | `4c6c5a3fdf313c936d3db870e94910569216753214237c7444089e8ccdf1382b` | `2026-08-15T09:00:08.363848Z` ~ `2026-08-15T09:09:51.588148Z` | P3/R13/L3 | OK (8,011 packets) |
| PCAP-059 | pcap | `capture/TEAM1-P3-R13-l3-20260815091004.pcap` | 569,763 | `eb66a98ea227dda94a4f4a35c661036e0cdfbba6d133d10f206ef44b974ba848` | `2026-08-15T09:10:04.028807Z` ~ `2026-08-15T09:20:03.417988Z` | P3/R13/L3 | OK (4,791 packets) |
| PCAP-060 | pcap | `capture/TEAM1-P3-R13-l3-20260815092004.pcap` | 34,517 | `c4c2e5420ca3c55364c241938e5a03fce671fb9ac369d0aaccf5a342603751f3` | `2026-08-15T09:20:04.050525Z` ~ `2026-08-15T09:20:15.913877Z` | P3/R13/L3 | OK (265 packets) |
| PCAP-061 | pcap | `capture/TEAM1-P3-R14-l1-20260815094002.pcap` | 642,233 | `18f7b146973c7a98675556c435a5a6aa099f7c033fb57e562baea8a9d97b3e95` | `2026-08-15T09:40:07.247906Z` ~ `2026-08-15T09:50:01.048201Z` | P3/R14/L1 | OK (5,320 packets) |
| PCAP-062 | pcap | `capture/TEAM1-P3-R14-l1-20260815095008.pcap` | 346,381 | `20b4df24bcf60fb218ba7853af7b76936e653658392cc13b09bf28c4367146a4` | `2026-08-15T09:50:08.060517Z` ~ `2026-08-15T10:00:06.158670Z` | P3/R14/L1 | OK (2,688 packets) |
| PCAP-063 | pcap | `capture/TEAM1-P3-R14-l1-20260815100011.pcap` | 14,195 | `edc99021f6e99d014205378c31a3bf77c9ad839743ecabbe85daaf304aea5e25` | `2026-08-15T10:00:11.283076Z` ~ `2026-08-15T10:00:15.687471Z` | P3/R14/L1 | OK (131 packets) |
| PCAP-064 | pcap | `capture/TEAM1-P3-R14-l2-20260815094002.pcap` | 766,546 | `a3c550d6f9c62e425ee4e623ac97b0cae66cb001c8f5240c54e5555ad96ab047` | `2026-08-15T09:40:07.438757Z` ~ `2026-08-15T09:49:58.260671Z` | P3/R14/L2 | OK (5,800 packets) |
| PCAP-065 | pcap | `capture/TEAM1-P3-R14-l2-20260815095002.pcap` | 989,946 | `0bc92a1b7a5903c952a7dd564841c16bc4e694340bda29f2a3e975abb0005982` | `2026-08-15T09:50:02.034786Z` ~ `2026-08-15T10:00:01.736818Z` | P3/R14/L2 | OK (8,104 packets) |
| PCAP-066 | pcap | `capture/TEAM1-P3-R14-l2-20260815100002.pcap` | 53,058 | `35a6753c73fadf78a8a653c9389d388d39cc788a118a5bfedff2d0abfdd2a3b3` | `2026-08-15T10:00:01.981154Z` ~ `2026-08-15T10:00:15.738153Z` | P3/R14/L2 | OK (426 packets) |
| PCAP-067 | pcap | `capture/TEAM1-P3-R14-l3-20260815094002.pcap` | 1,762,019 | `6e520e53856916dd480d3a2636abc5e790ed760c3e92e2450454399072ce5eb6` | `2026-08-15T09:40:07.432297Z` ~ `2026-08-15T09:49:43.508470Z` | P3/R14/L3 | OK (13,744 packets) |
| PCAP-068 | pcap | `capture/TEAM1-P3-R14-l3-20260815095002.pcap` | 1,046,365 | `ef31e82e597c968c78edc60a8b180bcc32812033b8f5cb59f2db03236b77db7e` | `2026-08-15T09:50:01.925550Z` ~ `2026-08-15T10:00:01.725310Z` | P3/R14/L3 | OK (8,438 packets) |
| PCAP-069 | pcap | `capture/TEAM1-P3-R14-l3-20260815100002.pcap` | 54,816 | `2bbb58fe747fcf0eb6fed2b7a365c4e938317a7cc6ace1bbe5319a96486b9da5` | `2026-08-15T10:00:01.960066Z` ~ `2026-08-15T10:00:15.934555Z` | P3/R14/L3 | OK (442 packets) |
| PCAP-070 | pcap | `capture/TEAM1-P3-R15-l1-20260815102002.pcap` | 619,696 | `e9860725a70f10998f4223f63269f54b3c1180c6c8234d663d3ee70bcb68164b` | `2026-08-15T10:20:06.934495Z` ~ `2026-08-15T10:30:01.547787Z` | P3/R15/L1 | OK (5,140 packets) |
| PCAP-071 | pcap | `capture/TEAM1-P3-R15-l1-20260815103003.pcap` | 326,335 | `035beea47191bf130c42495079b7632d3c4e70460a3ccb121ac8e19c39caa41c` | `2026-08-15T10:30:03.496589Z` ~ `2026-08-15T10:40:01.048213Z` | P3/R15/L1 | OK (2,535 packets) |
| PCAP-072 | pcap | `capture/TEAM1-P3-R15-l1-20260815104014.pcap` | 3,692 | `fd5eddff455cef7ed4c4c6fd5f6e387275ed803b301456318416ce73dd74f8e0` | `2026-08-15T10:40:13.623262Z` ~ `2026-08-15T10:40:21.070731Z` | P3/R15/L1 | OK (35 packets) |
| PCAP-073 | pcap | `capture/TEAM1-P3-R15-l2-20260815102002.pcap` | 818,636 | `aa0c941cc9513e5903cfe1a4696983e33e0a1b264ec7f47857dea21f15901d11` | `2026-08-15T10:20:07.039095Z` ~ `2026-08-15T10:29:56.930769Z` | P3/R15/L2 | OK (6,382 packets) |
| PCAP-074 | pcap | `capture/TEAM1-P3-R15-l2-20260815103002.pcap` | 925,848 | `437a53c0681a8e84ee290357e1210ae7b7759be21495d82d0c24fd5da1e3aae4` | `2026-08-15T10:30:02.016758Z` ~ `2026-08-15T10:40:01.525265Z` | P3/R15/L2 | OK (7,759 packets) |
| PCAP-075 | pcap | `capture/TEAM1-P3-R15-l2-20260815104002.pcap` | 54,148 | `6f6b364ee11c035df71e02ba705fc3778888ee30d29301b2e9f92a648c9d23eb` | `2026-08-15T10:40:02.008966Z` ~ `2026-08-15T10:40:22.151404Z` | P3/R15/L2 | OK (425 packets) |
| PCAP-076 | pcap | `capture/TEAM1-P3-R15-l3-20260815102002.pcap` | 1,154,850 | `d657ae8b29b17c9534cf72ca904fbd121c89cd1e250cbb7671f425f5630b4802` | `2026-08-15T10:20:07.142995Z` ~ `2026-08-15T10:29:58.791544Z` | P3/R15/L3 | OK (9,059 packets) |
| PCAP-077 | pcap | `capture/TEAM1-P3-R15-l3-20260815103003.pcap` | 611,677 | `33b8dbf76705699a1c22541d8a0e8ecad6236fe283b13132a1c633412dbf598d` | `2026-08-15T10:30:03.511948Z` ~ `2026-08-15T10:40:02.649341Z` | P3/R15/L3 | OK (5,167 packets) |
| PCAP-078 | pcap | `capture/TEAM1-P3-R15-l3-20260815104003.pcap` | 45,110 | `4373e508e8331ddc11bf12842863d13da705420bbc19f616193a9fbf4ed16c8e` | `2026-08-15T10:40:02.889054Z` ~ `2026-08-15T10:40:22.231942Z` | P3/R15/L3 | OK (346 packets) |
| PCAP-079 | pcap | `capture/TEAM1-P3-R16-l1-20260815110002.pcap` | 668,351 | `6ebc1de8ae3d27eb9ceae6ddcbf3f7b2ab77a3de33d3433c5791a071ae7c7d4c` | `2026-08-15T11:00:07.386364Z` ~ `2026-08-15T11:10:01.048269Z` | P3/R16/L1 | OK (5,383 packets) |
| PCAP-080 | pcap | `capture/TEAM1-P3-R16-l1-20260815111009.pcap` | 334,105 | `154d710ef9f7693069fa7846e09195b99a5fa66bfeaa1c23789f24bd85a433e3` | `2026-08-15T11:10:08.189458Z` ~ `2026-08-15T11:20:04.068985Z` | P3/R16/L1 | OK (2,684 packets) |
| PCAP-081 | pcap | `capture/TEAM1-P3-R16-l1-20260815112012.pcap` | 12,749 | `dd0e0f02be12cc5c886769ca050796284de98877896e4a5d454ddd9f1d573baa` | `2026-08-15T11:20:11.608468Z` ~ `2026-08-15T11:20:16.408705Z` | P3/R16/L1 | OK (116 packets) |
| PCAP-082 | pcap | `capture/TEAM1-P3-R16-l2-20260815110002.pcap` | 808,743 | `c0cbd426b3f8e65efc10221815f10ec594caba55f801a36614b635e6de473e04` | `2026-08-15T11:00:07.624402Z` ~ `2026-08-15T11:09:53.373561Z` | P3/R16/L2 | OK (6,378 packets) |
| PCAP-083 | pcap | `capture/TEAM1-P3-R16-l2-20260815111002.pcap` | 1,365,102 | `3f8d3cadfe4973a0bb04eb4ef93369fdea17799483a16bcb55be7a09fe086215` | `2026-08-15T11:10:02.033522Z` ~ `2026-08-15T11:20:01.128399Z` | P3/R16/L2 | OK (11,160 packets) |
| PCAP-084 | pcap | `capture/TEAM1-P3-R16-l2-20260815112002.pcap` | 21,670 | `baa64fa035c7b9e79785a8c62fd7391f632c55ef5b25dc5874e7b00940a7943c` | `2026-08-15T11:20:02.027572Z` ~ `2026-08-15T11:20:16.403187Z` | P3/R16/L2 | OK (208 packets) |
| PCAP-085 | pcap | `capture/TEAM1-P3-R16-l3-20260815110002.pcap` | 1,163,792 | `e2b3062137b6304b28317742106f24a1120aeae019eec9d38d799f9982e7ea35` | `2026-08-15T11:00:07.636528Z` ~ `2026-08-15T11:09:54.399193Z` | P3/R16/L3 | OK (9,082 packets) |
| PCAP-086 | pcap | `capture/TEAM1-P3-R16-l3-20260815111004.pcap` | 344,777 | `6539c2ee65b3c2eafa17195afca865502a945facfba7d089c38c8589892be872` | `2026-08-15T11:10:04.035026Z` ~ `2026-08-15T11:20:03.511081Z` | P3/R16/L3 | OK (2,869 packets) |
| PCAP-087 | pcap | `capture/TEAM1-P3-R16-l3-20260815112005.pcap` | 19,862 | `39db991e3e512ab8dc6a683ef3f121dbf80f136f865c79b399f96e353e969f49` | `2026-08-15T11:20:04.028791Z` ~ `2026-08-15T11:20:17.096264Z` | P3/R16/L3 | OK (172 packets) |
| PCAP-088 | pcap | `capture/TEAM1-P3-R17-l1-20260815114002.pcap` | 2,350,959 | `23296766165032af46c8f7922143d46d1d404f81a9a52bd0fd469060a8ad3daf` | `2026-08-15T11:40:07.260558Z` ~ `2026-08-15T11:50:01.048231Z` | P3/R17/L1 | OK (19,575 packets) |
| PCAP-089 | pcap | `capture/TEAM1-P3-R17-l1-20260815115008.pcap` | 1,922,786 | `09ec59a725169cd6e379805dba45aecfe843f84467fcb2994bf1792b9999ec54` | `2026-08-15T11:50:08.066095Z` ~ `2026-08-15T12:00:01.048226Z` | P3/R17/L1 | OK (16,015 packets) |
| PCAP-090 | pcap | `capture/TEAM1-P3-R17-l2-20260815114002.pcap` | 2,602,877 | `e602be17e8734e36c82fb8e1b23f9cbb9408139218b45037dc238f3db669538e` | `2026-08-15T11:40:07.380594Z` ~ `2026-08-15T11:50:01.340532Z` | P3/R17/L2 | OK (21,241 packets) |
| PCAP-091 | pcap | `capture/TEAM1-P3-R17-l2-20260815115002.pcap` | 1,953,988 | `4eb29f7b23fa08fe677cd8156a76c349577eb9758a16729b839daf098ab684c2` | `2026-08-15T11:50:01.819755Z` ~ `2026-08-15T12:00:01.812984Z` | P3/R17/L2 | OK (16,061 packets) |
| PCAP-092 | pcap | `capture/TEAM1-P3-R17-l2-20260815120002.pcap` | 180,503 | `25ef1dd7c47f4ca029d90d29490eb91f347de6524c57a578f83aad65afb35a4c` | `2026-08-15T12:00:01.845332Z` ~ `2026-08-15T12:00:15.598353Z` | P3/R17/L2 | OK (1,483 packets) |
| PCAP-093 | pcap | `capture/TEAM1-P3-R17-l3-20260815114002.pcap` | 2,558,532 | `b14ade70d659036a06a1af2366afaca07ba53876e005a82ca07ab93fc2197e36` | `2026-08-15T11:40:07.600937Z` ~ `2026-08-15T11:50:01.730781Z` | P3/R17/L3 | OK (21,010 packets) |
| PCAP-094 | pcap | `capture/TEAM1-P3-R17-l3-20260815115002.pcap` | 3,319,226 | `7f932749c6e3ea7fd920421594ab7a4cae2be3d22bf3628047411fc66706d71a` | `2026-08-15T11:50:01.760366Z` ~ `2026-08-15T11:59:58.306681Z` | P3/R17/L3 | OK (27,594 packets) |
| PCAP-095 | pcap | `capture/TEAM1-P3-R17-l3-20260815120003.pcap` | 11,477 | `3cffa6c8bca05a0b1e3eec80896be738c5130431395e15ecef0f47a80690da16` | `2026-08-15T12:00:03.736943Z` ~ `2026-08-15T12:00:15.578803Z` | P3/R17/L3 | OK (98 packets) |
| PCAP-096 | pcap | `capture/TEAM1-P3-R18-l1-20260815122002.pcap` | 4,592,042 | `c4b9c3230a5782ae53fa6f2772b90a8efd6ecab44dd636ad6319ea591d5768d1` | `2026-08-15T12:20:07.501441Z` ~ `2026-08-15T12:30:01.939557Z` | P3/R18/L1 | OK (39,443 packets) |
| PCAP-097 | pcap | `capture/TEAM1-P3-R18-l1-20260815123002.pcap` | 4,154,927 | `d0a0c6419fafe5026c8fdd45aff68f19117a5332e23220c116222cb7c06d45e5` | `2026-08-15T12:30:01.970064Z` ~ `2026-08-15T12:40:00.087994Z` | P3/R18/L1 | OK (35,835 packets) |
| PCAP-098 | pcap | `capture/TEAM1-P3-R18-l1-20260815124002.pcap` | 114,720 | `d586c12fc43af1f449aa2123a2f717145c7913a4fd9e6cbe1a0d5533432d20b9` | `2026-08-15T12:40:01.048198Z` ~ `2026-08-15T12:40:17.443263Z` | P3/R18/L1 | OK (1,018 packets) |
| PCAP-099 | pcap | `capture/TEAM1-P3-R18-l2-20260815122002.pcap` | 3,397,011 | `2d23e409c85c3dfc6bf397e266934e68afb615fa9e45874751cf575a88bea9ec` | `2026-08-15T12:20:07.659549Z` ~ `2026-08-15T12:30:01.444574Z` | P3/R18/L2 | OK (27,844 packets) |
| PCAP-100 | pcap | `capture/TEAM1-P3-R18-l2-20260815123002.pcap` | 2,684,294 | `ef0d42c83260865e0bbf156881390db4ec4c577c0cafa58dca7562d312e1c4ab` | `2026-08-15T12:30:02.014642Z` ~ `2026-08-15T12:40:00.981586Z` | P3/R18/L2 | OK (22,144 packets) |
| PCAP-101 | pcap | `capture/TEAM1-P3-R18-l2-20260815124002.pcap` | 206,948 | `25a46ad01938032ffd7748746ead54f238c459cd4555602dd6f4cf57a0f6525b` | `2026-08-15T12:40:01.014189Z` ~ `2026-08-15T12:40:17.412197Z` | P3/R18/L2 | OK (1,713 packets) |
| PCAP-102 | pcap | `capture/TEAM1-P3-R18-l3-20260815122002.pcap` | 2,275,214 | `a086875c135a17cfcfe28f165771744c85311bada92092eb49eea9e593eaf4d7` | `2026-08-15T12:20:07.603270Z` ~ `2026-08-15T12:29:52.957284Z` | P3/R18/L3 | OK (18,519 packets) |
| PCAP-103 | pcap | `capture/TEAM1-P3-R18-l3-20260815123003.pcap` | 2,264,366 | `b4c16bebcc3a58532ba56604c3203a4145ad56156c66bd753461a4b5a5fc3d7d` | `2026-08-15T12:30:03.316806Z` ~ `2026-08-15T12:39:56.043380Z` | P3/R18/L3 | OK (18,766 packets) |
| PCAP-104 | pcap | `capture/TEAM1-P3-R18-l3-20260815124004.pcap` | 368 | `23862e7b69d66ab7a020e7d9e3d2423e672448170f8e2054724e252af3a6352f` | `2026-08-15T12:40:04.029582Z` ~ `2026-08-15T12:40:17.434301Z` | P3/R18/L3 | OK (4 packets) |
<!-- PCAP_INVENTORY_END -->

### 3.2 Log 21개

<!-- LOG_INVENTORY_START -->
| Evidence ID | 유형 | 파일명 | 크기 | SHA-256 | 시간 범위 (UTC) | 추정 Phase/Round | 파싱 상태 |
|---|---|---|---:|---|---|---|---|
| LOG-A-P2-R10 | attacker JSONL log | `log/attacker/R10/TEAM1-P2-R10-attacker.log` | 9,698 | `7a74313b22b91c8968b2a1dbb1b102d5a236d8f44a68d92a38d607c30dc040a4` | `timestamp 없음` | P2/R10 | OK (57 records, JSON errors 0) |
| LOG-A-P2-R11 | attacker JSONL log | `log/attacker/R11/TEAM1-P2-R11-attacker.log` | 1,779 | `a29415a02508a35085a786de181aa29ae8b5d23587bd38495aee74fb6c7d222a` | `timestamp 없음` | P2/R11 | OK (16 records, JSON errors 0) |
| LOG-A-P2-R12 | attacker JSONL log | `log/attacker/R12/TEAM1-P2-R12-attacker.log` | 7,912 | `a181b422a812998a839c3ed657567c1abe6b6444caf4ab2545098413641efd78` | `timestamp 없음` | P2/R12 | OK (57 records, JSON errors 0) |
| LOG-A-P3-R13 | attacker JSONL log | `log/attacker/R13/TEAM1-P3-R13-attacker.log` | 3,730 | `fb2e63f14fff0063546d3a600c29bfe53d2684549a0d8c4e16b6f06ad7fc7523` | `timestamp 없음` | P3/R13 | OK (31 records, JSON errors 0) |
| LOG-A-P3-R14 | attacker JSONL log | `log/attacker/R14/TEAM1-P3-R14-attacker.log` | 3,730 | `21cc5f78eb9bd190dc886974fe33fc4aa95d6061e9eb356a6237fb0d8e04e440` | `timestamp 없음` | P3/R14 | OK (31 records, JSON errors 0) |
| LOG-A-P3-R15 | attacker JSONL log | `log/attacker/R15/TEAM1-P3-R15-attacker.log` | 2,273 | `633bc6c5a86499f63eef3d8b96be92fa3630f58af664cde557130e1ff4260bd6` | `timestamp 없음` | P3/R15 | OK (13 records, JSON errors 0) |
| LOG-A-P3-R16 | attacker JSONL log | `log/attacker/R16/TEAM1-P3-R16-attacker.log` | 2,211 | `171db149282b2409d43598b59ab5acb9cf016dd6cd29556a1ba81cd7c7b18665` | `timestamp 없음` | P3/R16 | OK (13 records, JSON errors 0) |
| LOG-A-P3-R17 | attacker JSONL log | `log/attacker/R17/TEAM1-P3-R17-attacker.log` | 3,309 | `af454e587e379ff510d8e0318c803635af5513c5ac1021010850574989ebe001` | `timestamp 없음` | P3/R17 | OK (27 records, JSON errors 0) |
| LOG-A-P3-R18 | attacker JSONL log | `log/attacker/R18/TEAM1-P3-R18-attacker.log` | 2,142 | `46c605770e66bef2c625db403c9f8038c4b3f7fb0e48ceefab3b9061889c6134` | `timestamp 없음` | P3/R18 | OK (13 records, JSON errors 0) |
| LOG-A-P2-R09 | attacker JSONL log | `log/attacker/R9/TEAM1-P2-R9-attacker.log` | 11,736 | `16d98ff8dfa1d2cca8604f0c46c97ea856a3c2d501ebe56eb978ec86f16f9b0c` | `timestamp 없음` | P2/R9 | OK (79 records, JSON errors 0) |
| LOG-D-P2-R10 | defender JSONL log | `log/defender/R10/TEAM1-P2-R10-defender.log` | 49,105 | `6d78445d263f36001a034c4aaf3f83911c5a4650f885b4705ef1a0a3f5edf6fb` | `2026-08-15T07:00:09.802000Z ~ 2026-08-15T07:20:04.915000Z` | P2/R10 | OK (234 records, JSON errors 0) |
| LOG-D-P2-R11 | defender JSONL log | `log/defender/R11/TEAM1-P2-R11-defender.log` | 48,441 | `9cc438320f75a6f5e56ee1750f1051aba9758880f2cb2377dc3938e555ba55cf` | `2026-08-15T07:40:08.984000Z ~ 2026-08-15T08:00:07.191000Z` | P2/R11 | OK (231 records, JSON errors 0) |
| LOG-D-P2-R12 | defender JSONL log | `log/defender/R12/TEAM1-P2-R12-defender.log` | 44,747 | `12618b67b3089bad28706aecf71f81e7ff7f00d119ae1a3e923d7aa4f94667ca` | `2026-08-15T08:20:05.201000Z ~ 2026-08-15T08:40:10.862000Z` | P2/R12 | OK (214 records, JSON errors 0) |
| LOG-D-P3-R13 | defender JSONL log | `log/defender/R13/TEAM1-P3-R13-defender.log` | 42,227 | `7cae3c2e5cc3debd9f0d2a7e959f12fdd6dcea032641ef2eb6b4bdc259f18a2c` | `2026-08-15T09:00:07.398000Z ~ 2026-08-15T09:20:08.994000Z` | P3/R13 | OK (202 records, JSON errors 0) |
| LOG-D-P3-R14 | defender JSONL log | `log/defender/R14/TEAM1-P3-R14-defender.log` | 48,096 | `492d226aa0ce19b7ce011393c0d7513fdd60044c1cf8c1583ed6e2524ff690c2` | `2026-08-15T09:40:06.907000Z ~ 2026-08-15T10:00:05.159000Z` | P3/R14 | OK (229 records, JSON errors 0) |
| LOG-D-P3-R15 | defender JSONL log | `log/defender/R15/TEAM1-P3-R15-defender.log` | 46,758 | `d783e03ddf32cb5cba208555056189cb121efd38d9babd5e8bd2b6ceea258cb6` | `2026-08-15T10:20:06.722000Z ~ 2026-08-15T10:40:09.117000Z` | P3/R15 | OK (223 records, JSON errors 0) |
| LOG-D-P3-R16 | defender JSONL log | `log/defender/R16/TEAM1-P3-R16-defender.log` | 44,167 | `dc366633a356e395e30cdd9f8d9bbfcbe37c663d2eebd1bbcf334d994cd2940f` | `2026-08-15T11:00:07.090000Z ~ 2026-08-15T11:20:03.751000Z` | P3/R16 | OK (211 records, JSON errors 0) |
| LOG-D-P3-R17 | defender JSONL log | `log/defender/R17/TEAM1-P3-R17-defender.log` | 35,488 | `6362b2cf418b68a4bb05d62e3180fada05c26ca2b2e1a6be308514cadddf5be8` | `2026-08-15T11:40:06.914000Z ~ 2026-08-15T12:00:02.066000Z` | P3/R17 | OK (169 records, JSON errors 0) |
| LOG-D-P3-R18 | defender JSONL log | `log/defender/R18/TEAM1-P3-R18-defender.log` | 42,313 | `f03910b6dcb802ed7ff0454b833e139cc90cf8a816d2949574fa13f85a25e415` | `2026-08-15T12:20:07.247000Z ~ 2026-08-15T12:40:06.266000Z` | P3/R18 | OK (201 records, JSON errors 0) |
| LOG-D-P2-R08 | defender JSONL log | `log/defender/R8/TEAM1-P2-R8-defender.log` | 3,263 | `5e021b75732a14a5c4e09a25d4f150db8792027f814e5c9c930b46aafb833d31` | `2026-08-15T05:40:09.426000Z ~ 2026-08-15T05:59:27.808000Z` | P2/R8 | OK (22 records, JSON errors 0) |
| LOG-D-P2-R09 | defender JSONL log | `log/defender/R9/TEAM1-P2-R9-defender.log` | 3,263 | `944e65a48b94d18d05dd149c79b79cca5ec691a002d9da06a40f42b3e313a003` | `2026-08-15T06:20:09.198000Z ~ 2026-08-15T06:39:28.165000Z` | P2/R9 | OK (22 records, JSON errors 0) |
<!-- LOG_INVENTORY_END -->

### 3.3 Linux live validation evidence

아래 항목은 저장소에 복사하지 않은 일회성 Docker/agent 집계 로그다. 원문 비밀이나 raw frame은 기록하지 않았다.

| Evidence ID | 유형 | 환경 | 관측 | 상태 |
|---|---|---|---|---|
| `LIVE-001` | Broker E2E | 공식 스켈레톤, Linux/amd64, Team 1 | Defender 집계 36 verdict의 send E2E p99/max 552.070 us; Router 누적 46 forwarded/46 ACCEPT/0 DROP/0 GC drop, send failure·deadline 강제 DROP 0 | OK, ACCEPT 경로 한정 |
| `LIVE-002` | reconnect | Team 1 Router 강제 재시작 | `broker-eof` 뒤 bounded backoff를 거쳐 0.751초 안에 `session_id=2`; 다음 health summary의 sessions=2 | OK |
| `LIVE-003` | lifecycle | Team 1 attacker Docker stop | 수정 전 SIGTERM 뒤 SIGKILL·exit 137, OOM=false; 수정 후 `signal` signum 15 기록·1초 내 exit 0, OOM=false | OK after fix |
| `LIVE-004` | skeleton service startup | 공식 L1–L3 challenge containers | 6개 layer container가 gunicorn gevent의 `packaging` 모듈 누락으로 restart loop | BLOCKED, 외부 스켈레톤 미수정 |
| `LIVE-005` | merge-candidate rerun | 공식 스켈레톤, Linux/amd64, Team 1 | 35 verdict send E2E p99/max 530.152 us, Router snapshot 63 forwarded/63 ACCEPT/0 DROP/0 GC drop; reconnect 0.752초; attacker SIGTERM exit 0; 6개 layer restart 재현 | OK, challenge는 동일 외부 차단 |

## 4. PCAP 분석 결과

### 4.1 전체 메타데이터

- 총 104개, 105,148,605 bytes, 868,991 TCP packet.
- 시간 범위: `2026-08-15T01:00:14.748452Z`–`2026-08-15T12:40:17.443263Z`.
- 관측 프로토콜: Ethernet/IPv4/TCP/HTTP. UDP 및 그 밖의 IP protocol은 관측되지 않았다.
- TCP SYN 128,478, FIN 127,065, RST 37,878, payload segment 208,819.
- HTTP request: GET 77,653, POST 1,614, HEAD 207. HTTP 429는 0건.
- 동일 방향 sequence overlap/retransmission 후보 18,084건, forward gap/out-of-order 후보 1,522건이다. 이는 캡처 손실을 포함할 수 있으므로 `INFERRED`이며 tshark 부재로 확정하지 않는다.
- packet-local complete HTTP request는 79,474건이었다.
- 요청·응답 상관 지연은 p50 2.123 ms, p95 5.450 ms, p99 14.551 ms였다. max 579.72초는 FIFO 상관 오차로 판단되는 outlier이며 300ms SLA 근거로 사용하지 않는다.
- 공식 운영세칙 제12조는 레이어 네트워크에 30ms 지연·0.3% loss 모사를 명시한다. 위 PCAP 지연은 capture point와 FIFO 결합에 종속된 로컬 관찰값이므로 공식 네트워크 E2E 지연으로 해석하지 않는다.

### 4.2 현재 방어 정책 재생

`2026-08-18T00:00:00Z`를 policy 평가 시각으로 고정해 104개 전체를 재생했다.

| 항목 | 결과 |
|---|---:|
| policy bundle | `defender-2026-08-15-full-corpus-hardening` |
| 전체 rule / DROP 가능 rule | 22 / 9 |
| demotion | 0 |
| 관측 exploit shape | 14,407 |
| 차단된 exploit shape | 14,407 (100%) |
| flag-linked request | 2,133 |
| 차단된 flag-linked request | 2,121 |
| other request | 65,067 |
| 예상 밖 other DROP | 0 |
| incomplete/coalesced other | 21 |

실제 분할 경계에서도 bounded stitcher가 작동한 증거로, 완전한 packet-local HTTP request가 아니면서 DROP된 packet이 89건 있었다. rule별로 helper-secret 44, forged-admin-session 31, app-meta-union 14건이다.

### 4.3 실제 관측된 성공·실패 형태

민감 payload 원문 대신 구조 fingerprint만 기록한다.

| Exploit-shape ID | Layer | 구조 | 전체 시도 | flag-linked | 관찰 |
|---|---|---|---:|---:|---|
| `EXP-L1-HELPER-SSRF` | L1 | bounded fetch route + helper service + secret path | 5,814 | 1,016 | canonical service-name 형태가 대부분이며 IPv4/hex/integer/IPv4-mapped 변형은 각 1건 성공 |
| `EXP-L1-CONFIG-TRAVERSAL` | L1 | bounded config route + traversal depth | 1,944 | 1 | depth 4만 1건 연결, 나머지 depth는 0 |
| `EXP-L2-FORGED-ADMIN` | L2 | Base64 JSON session + bounded admin claim | 3,857 | 932 | `/admin`과 구조화된 claim 조합 |
| `EXP-L2-SECRET-SSRF` | L2 | bounded fetch route + loopback service + secret path | 835 | 1 | canonical 조합만 flag-linked |
| `EXP-L2-REGISTRY-SSRF` | L2 | bounded fetch host parameter + loopback service + registry path | 876 | 1 | short-loopback 조합만 flag-linked |
| `EXP-L3-APP-META-SQLI` | L3 | bounded app metadata query + UNION shape | 1,081 | 171 | block-comment 8/8, dash-comment 70/384, no-comment 93/689 |

flag-linked이지만 위 exploit label 밖에서 ACCEPT된 12개 요청은 `/`, `/admin`, `/debug`, `/rc/status`, `/teleop/status`에 분포했고 일부는 404 응답과 연결됐다. request/response FIFO 귀속 오차 가능성이 있어 새 rule 근거로 사용하지 않는다.

## 5. Log 분석 결과

### 5.1 공격자 로그 10개

| Round | accepted | requests | LLM calls | tokens | observed |
|---|---:|---:|---:|---:|---:|
| P2/R9 | 4 | 6,802 | 80 | 60,003 | 242 |
| P2/R10 | 4 | 7,451 | 80 | 60,023 | 242 |
| P2/R11 | 0 | 3,051 | 160 | 120,882 | 88 |
| P2/R12 | 2 | 6,823 | 80 | 60,246 | 242 |
| P3/R13 | 1 | 5,147 | 160 | 121,409 | 165 |
| P3/R14 | 1 | 5,331 | 160 | 121,787 | 165 |
| P3/R15 | 1 | 5,786 | 160 | 121,643 | 165 |
| P3/R16 | 1 | 5,809 | 160 | 121,155 | 165 |
| P3/R17 | 2 | 4,634 | 160 | 135,834 | 99 |
| P3/R18 | 2 | 5,042 | 160 | 134,984 | 99 |

- hit 150건: fetch-url 계열 142, admin 계열 8.
- 선택 이유: deterministic SSRF pivot 90, playbook 44, deterministic L1 8, deterministic L2 8.
- `PlanBindingError` reject 11건, no-response skip 102건.
- accepted 외 duplicate/own_team/rejected/closed 및 429는 관측되지 않았다.
- summary 수치는 round 내 누적이다. accepted가 일찍 정체된 뒤 requests와 tokens가 계속 증가한 round가 있어 예산 낭비 가능성이 있다.
- 현재 branch에는 completed-endpoint 추적, 30초 고정 cooldown, round playbook이 이미 존재한다. 실패 누적에 따른 progressive backoff는 없다.
- 10개 로그 모두 event timestamp가 없어 flow, flag 후보 발견, 제출 결과를 PCAP과 정밀 연결할 수 없었다.

### 5.2 방어자 로그 11개

- P2/R8–R9는 shadow baseline이며 DROP 가능 rule 0개.
- P2/R10–P3/R16은 `l2-enforce`, DROP 가능 rule 6개.
- P3/R17–R18은 `team1-capture-enforce`, DROP 가능 rule 4개.
- policy load error 또는 demotion은 0건, session-connected는 파일당 1건.
- anomaly alert 1,717건은 모두 `alert-only-no-policy-change`: baseline violation 928, raw drop rate 783, rule concentration 6.
- advisory 219건, 총 172,433 tokens, model `gpt-4o-mini`.
- 과거 로그에는 heartbeat, packet verdict, parser failure, queue overflow, latency, shutdown summary가 없어 해당 항목은 `UNKNOWN`이다. 현재 branch에는 shutdown metrics와 watchdog가 있으나 과거 증거를 소급 생성하지 않는다.

## 6. PCAP·Log 상관분석

| 판단 | 분류 | Evidence | 결과 |
|---|---|---|---|
| defender lifecycle와 round capture 시작 | CONFIRMED | `LOG-D-P2-R08`–`LOG-D-P3-R18`, 동일 round PCAP | defender startup은 첫 PCAP packet보다 0.178–0.788초 앞섰다. |
| P2/R8–R9 shadow와 exploit/flag response 공존 | CONFIRMED (round 수준) | `LOG-D-P2-R08`, `LOG-D-P2-R09`, 해당 PCAP | DROP 가능 rule 0 상태에서 실제 exploit/flag-linked 흐름이 존재했다. packet별 verdict가 없어 exact verdict는 UNKNOWN이다. |
| 현재 policy의 known-shape 차단 | OBSERVED | `PCAP-001`–`PCAP-104` | 14,407/14,407 차단, 예상 밖 other DROP 0. 공식 Broker SLA 증명은 아니다. |
| attacker flag 제출 성공 | OBSERVED | `LOG-A-P2-R09`–`LOG-A-P3-R18` | round별 accepted 0–4건. timestamp 부재로 해당 flow와 exact 결합 불가. |
| TCP 재전송·분할 | INFERRED | `PCAP-001`–`PCAP-104` | sequence overlap/gap 및 headerless DROP이 존재하나 tshark expert 정보가 없어 exact 분류 불가. |
| P4/L4 공격·방어 동작 | UNKNOWN | 해당 capture/log Evidence 없음 | 공식 안내로 P4에서 L4가 개방됨은 확인했지만 L4 전략·규칙을 실트래픽 근거 없이 추가할 수 없다. |
| 공식 Broker ACCEPT E2E | OBSERVED | `LIVE-001`, `LIVE-005` | 두 Linux `SOCK_SEQPACKET` 실행에서 health 표본 p99/max 552.070 us와 530.152 us, Router 46/46 및 63/63 ACCEPT를 확인했다. 관측된 ACCEPT 경로의 300 ms 계약만 확인했다. |
| Broker reconnect | OBSERVED | `LIVE-002`, `LIVE-005` | Router restart 뒤 EOF를 감지하고 각각 0.751초, 0.752초 안에 새 session을 수립했다. 실제 in-flight verdict가 있던 시점은 아니므로 stale verdict 격리는 unit test 근거만 있다. |
| 공격자 정상 종료 | OBSERVED | `LIVE-003`, `LIVE-005` | 수정 전 exit 137을 재현했고 수정 후 두 차례 동일 SIGTERM에서 audit signum 15와 exit 0을 확인했다. |
| 실제 공격·DROP·flag/SLA 효과 | UNKNOWN | `LIVE-004` | 공식 challenge 서비스가 외부 의존성 누락으로 기동하지 않아 exploit delivery, DROP verdict, flag 획득, 서비스 가용성 효과는 측정하지 못했다. |

## 7. Gap 보고

| ID | 영역 | Capture/Log 증거 | 현재 코드 동작 | 문제 | 본선 영향 | 권장 개선 | 소유자 | 우선순위 |
|---|---|---|---|---|---|---|---|---|
| GAP-001 | 관측성·로그 품질 | 공격자 로그 10개 전체 | authoritative epoch `ts` 구현 | 과거 로그는 복구 불가 | 향후 상관분석은 가능 | caller override 회귀 테스트 유지 | 공격자 owner | P0 해결 |
| GAP-002 | 요청·토큰 예산 | `LOG-A-*`, accepted 정체 후 누적 증가 | completed endpoint + 고정 30초 cooldown | 반복 실패 강도에 관계없이 재시도 | 10 req/s·burst·token 예산 낭비 | endpoint/service fingerprint별 capped exponential cooldown 설계 delta | 공격자 owner | P1 |
| GAP-003 | 공격 탐색·적응성 | `LOG-A-*`, no-response 102·binding reject 11 | defer/release/retry reason·cooldown·playbook generation audit 구현 | progressive backoff와 evidence TTL은 미구현 | stale playbook·예산 낭비 가능 | observation-plan-execution design delta 승인 후 scheduler 변경 | 공격자 owner + 팀장 | P1 부분 해결 |
| GAP-004 | TCP 분할·재조립 | headerless DROP 89 | bounded stitcher 존재 | regression 범위 유지 필요 | 분할 우회 재발 위험 | capture-derived 최소 합성 split fixture 유지 | 방어자 owner | P0 유지 |
| GAP-005 | 방어 오탐·가용성 | other 65,067, 예상 밖 DROP 0 | 9개 DROP rule | broad rule 추가 시 baseline 훼손 위험 | 정상 서비스 장애 | 신규 규칙은 SHADOW, bounded scope, negative corpus 통과 후 승격 | 방어자 owner + 팀장 | P0 유지 |
| GAP-006 | worker·heartbeat·reconnect | 과거 defender log에 health event 없음, `LIVE-001`–`002` | hot path 밖 60초 aggregate health summary 구현 | 과거 로그는 복구 불가 | 향후 고장·지연 추세 탐지 가능 | watchdog callback·bounded summary 회귀 유지 | 방어자 owner | P1 해결 |
| GAP-007 | TCP 분석 | overlap 18,084, gap 1,522 후보 | 표준 라이브러리 추정 | retransmission/out-of-order exact 분류 불가 | 병목 원인 오판 | tshark 제공 환경에서 재검증 | 팀장 | P1 |
| GAP-008 | 공격/방어 L4 | 공식 안내는 P4/L4 개방 명시, 실 capture/log는 없음 | branch에 L4 readiness 코드 존재 | 실제 L4 behavior 검증 불가 | 추측 기반 변경 위험 | L4 capture/log 확보 전 신규 runtime 전략·ACTIVE rule 금지 | 팀장 | P0 입력 차단 |
| GAP-009 | 300ms E2E | `LIVE-001`, ACCEPT p99/max 552.070 us | Linux Broker ACCEPT 경로 통과 | 실제 DROP·부하·loss 경로 미측정 | 공격 시 deadline·오탐 영향 미확정 | 정상 기동 skeleton에서 DROP 포함 부하 E2E 재검증 | 방어자 + Docker owner + 팀장 | P1 부분 해결 |
| GAP-012 | Docker·배포 | `LIVE-003` | SIGTERM을 정상 round 종료 경로로 전환 | 수정 전 3초 뒤 SIGKILL·exit 137 | summary 유실·비정상 종료 | signal audit 및 exit 0 회귀 유지 | 공격자 owner | P0 해결 |
| GAP-013 | 공식 스켈레톤 | `LIVE-004` | 팀 이미지 build/startup 정상 | challenge 6개가 외부 `packaging` 누락으로 restart | flag·DROP·공격 효과 검증 차단 | 운영진에 skeleton dependency defect 전달 후 재실행 | Docker owner + 팀장 | P0 외부 차단 |
| GAP-011 | 문서·증거 귀속 | 공식 14 Round와 파일명 R1–R18 충돌 | filename label로 집계 | 실제 본선 round 귀속 불확실 | phase별 결론 과대 일반화 위험 | 운영진 export manifest 또는 round mapping 확보 | 팀장 | P0 입력 확인 |
| GAP-010 | 문서 일관성 | capture에는 L1–L3만 존재 | demo 8085 hint 문서 존재 | 근거 계층 혼동 가능 | 잘못된 운영 가정 | capture 근거와 운영 hint를 명확히 구분 | 팀장 | P2 |

## 8. P0/P1/P2 구현 로드맵

| 우선순위 | Evidence | 단일 문제와 성공 조건 | 예상 변경 파일·첫 실패 테스트 | 위험·rollback | 소유자·reviewer·설계 gate |
|---|---|---|---|---|---|
| P0 (구현) | `LOG-A-*` | 모든 공격자 audit JSON에 caller가 덮어쓸 수 없는 수치형 epoch `ts`가 있고 기존 redaction 유지 | `audit.py`, `test_audit.py`; injectable clock·override test 선행 | hot-path 판단에 미사용, 필드 제거로 rollback | 공격자 owner; 전략 설계 변경 없음 |
| P0 (구현) | `LIVE-003` | Docker SIGTERM에서 signal audit 후 exit 0 | `__main__.py`, `test_main.py`; handler import red test 선행 | main-thread signal 제약; handler 제거로 rollback | 공격자 owner; Docker/contracts 변경 없음 |
| P0 유지 | `PCAP-001`–`104` | known exploit 100% 차단, unexpected other DROP 0, split 회귀 유지 | 기존 policy/replay tests | 신규 ACTIVE rule 금지로 rollback 불필요 | 방어자 owner + 팀장; hot-path 변경 시 승인 필요 |
| P1 (구현) | `LOG-A-*` | 기존 재시도 동작을 바꾸지 않고 cooldown·release·failure reason을 감사 가능하게 함 | `runtime.py`, `test_runtime.py`; missing event red test 선행 | 로그량 증가; event 제거로 rollback | 공격자 owner; observation-plan-execution 동작 변경 없음 |
| P1 (구현) | `LOG-D-*`, `LIVE-001`–`002` | 60초 aggregate health/latency event가 verdict hot path 밖에서 발행 | `main.py`, `watchdog.py`, lifecycle/watchdog tests; missing callback red test 선행 | 로그 I/O 비용; callback 제거로 rollback | 방어자 owner + 팀장; 승인된 300ms 구조 안 |
| P1 (설계 필요) | `LOG-A-*` | 실패 fingerprint별 cooldown·상한·TTL·중단 조건 명시 | scheduler/planner tests 우선 | 탐색 기회 감소; feature flag/기존 30초로 rollback | 공격자 owner + 팀장; observation-plan-execution design delta 승인 후 구현 |
| P1 | `PCAP-001`–`104` | tshark 기반 retransmission/out-of-order 통계 확정 | 분석 문서만 갱신 | runtime 영향 없음 | 팀장 |
| P1 | `LIVE-001`, `LIVE-004` | DROP·부하 포함 공식 Broker E2E p99 < 300ms 확인 | integration timing | skeleton 의존; team code rollback 없음 | 방어자 + Docker owner + 팀장 |
| P2 | 운영 hint | L4 문서의 증거 출처 구분 | docs test/check | runtime 영향 없음 | 팀장 |

## 9. 실제 구현 및 테스트

- 공격자 audit: injectable `time.time` 기반 epoch `ts`를 scrub 이후 authoritative field로 기록해 caller override를 막았다. 구현 전 clock 미지원과 override 실패를 각각 red test로 확인했다.
- 공격자 retry 관측성: `endpoint-deferred`, `endpoint-retry-released`, `endpoint-retry-scheduled`에 sanitized reason, 남은 cooldown, playbook generation을 기록했다. 기존 30초 cooldown과 요청 동작은 변경하지 않았다.
- 방어자 health: watchdog tick callback에서 60초마다 policy, session, heartbeat, queue/audit drop, counter, hot-path, verdict-send-E2E 집계를 출력한다. callback 예외는 격리하며 packet verdict 동기 경로에는 로그 I/O를 추가하지 않았다.
- 공격자 lifecycle: SIGTERM/SIGINT를 audit한 뒤 기존 `KeyboardInterrupt`·`finally` round cleanup 경로로 전환했다. `test_main.py`는 구현 전 import failure로 실패했고 구현 후 통과했다.
- Windows에는 `AF_UNIX`가 없을 수 있으므로 Linux 실소켓 전용 2개 테스트만 capability skip하도록 바꿨다. Linux Broker live가 이 skip을 대신 검증했다.
- 실제 flag/token/cookie/host/payload는 테스트나 문서에 넣지 않았고 기존 redaction 동작은 유지한다. `FLAG{abc123}`, `FLAG{never}` 등 명백한 합성 문자열만 redaction·runtime fixture로 사용한다.
- 공격 delivery, rate limit, planner, policy rule, verdict semantics, contracts, Dockerfile은 변경하지 않았다. 새 공격·방어 runtime 설계나 근거 없는 L4 동작도 추가하지 않았다.

## 10. 검증 결과

<!-- VALIDATION_START -->
- TDD red: clock 미지원, caller timestamp override, retry audit event 부재, defender health constant/callback 부재, signal handler import failure를 구현 전에 각각 확인했다.
- attacker 전체: 230 tests, OK.
- defender 전체: 340 tests, OK, Windows capability skip 2. 합성 HTTP 429 객체의 `ResourceWarning` 1건은 failure가 아니다.
- timing 전용 재검증: 10 tests, OK. policy p99 43.6 us, 1/100/550/1100 pkt/s hot-path p99 최대 63.4 us, 측정 max 147.7 us. 이는 로컬 unit timing이다.
- capture-derived replay: 104 files, 79,474 HTTP requests, 14,407/14,407 known exploit shapes blocked, 65,046 other passed + 21 coalesced, unexpected other DROP 0, exit 0.
- 공식 Linux/amd64 image build·startup smoke: 공격자 `aegis/attacker:latest`, 방어자 `aegis/defender:latest` 기동. 방어자는 uid 65534, capabilities ALL drop, no-new-privileges를 유지했다.
- Linux Broker ACCEPT E2E (`LIVE-001`): Defender 36 verdict send p99/max 552.070 us, Router 46 forwarded/46 ACCEPT/0 DROP/0 GC drop, send failure·forced timeout DROP·protocol error 0.
- Router restart (`LIVE-002`): `broker-eof` 후 bounded 0.05/0.1/0.2/0.4초 retry를 거쳐 0.751초 안에 session 2 연결, 컨테이너는 계속 정상 실행했다.
- attacker SIGTERM (`LIVE-003`): 수정 전 exit 137/SIGKILL을 재현했고 수정 후 signum 15 audit, 1초 내 exit 0, OOM=false를 확인했다.
- 공식 challenge startup (`LIVE-004`): 팀 코드와 무관한 외부 스켈레톤의 `packaging` 누락으로 L1–L3 6개 container가 restart loop에 들어가 flag·DROP·서비스 SLA 검증은 차단됐다. 외부 skeleton은 수정하지 않았다.
- merge-candidate Linux rerun (`LIVE-005`): 35 verdict health 표본의 send E2E p99/max 530.152 us, Router snapshot 63 forwarded/63 ACCEPT/0 DROP/0 GC drop, reconnect 0.752초, attacker SIGTERM exit 0을 재확인했다. 6개 challenge restart와 동일 `packaging` 오류도 재현됐다.
- `pwsh -NoProfile -File scripts/check-layout.ps1`: pass.
- `git diff --check`: pass.
- `git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'`: 출력 없음.
- 변경 대상의 추가 라인과 새 파일 secret-pattern scan: 실제 flag/token/cookie/session/credential/raw payload 없음. 탐지된 `FLAG{never}`와 문서의 `FLAG{abc123}`은 합성 테스트 설명뿐이다.
- `scripts/validate-skeleton.ps1`: 공식 skeleton 필수 구조·agent guide·Broker binary 검증 통과.
- `integration/run-with-skeleton.ps1 -ConfigOnly`: 기동 없이 병합 Compose 검증 통과. 공격·방어 build context가 모두 현재 저장소의 해당 agent 디렉터리를 가리켰다.
- 공식 운영세칙 PDF의 관련 페이지(일정·PCAP/log cadence·rate limit·Broker·실행 옵션·채점·금지행위)를 텍스트 추출과 시각 렌더로 확인했다. 원본은 수정하지 않았고 임시 PNG 4개는 확인 후 삭제했다.
- 검증 종료 후 `integration/run-with-skeleton.ps1 -Down`으로 `lig-demo` container와 network를 정리했다. named volume 삭제 옵션은 사용하지 않았다.
<!-- VALIDATION_END -->

## 11. 원본·비밀정보 보존 확인

- raw PCAP/log는 이동, 수정, 압축 해제, staging하지 않았다.
- 이 문서는 파일 hash와 aggregate fingerprint만 포함한다.
- 기존 사용자 미추적 문서 두 개는 삭제하거나 덮어쓰지 않았다.
- 원본 증거는 `.gitignore`에 의해 추적되지 않으며 최종 `git ls-files`와 diff scan으로 다시 확인한다.

## 12. 남은 위험과 다음 행동

- 남은 핵심 위험은 P4/L4 증거 부재, 공식 14 Round와 파일명 R1–R18 귀속 충돌, tshark 부재에 따른 TCP expert 분류 제한, 실제 DROP·부하·loss 경로의 Broker E2E 미측정, 외부 skeleton challenge dependency 결함이다.
- 다음 한 가지 행동: `docs/reviews/2026-08-20-organizer-skeleton-escalation.md`를 운영진에 전달해 정상 기동본과 canonical round mapping을 받은 뒤, P4/L4 capture·log를 포함한 실제 DROP/flag/SLA live 검증을 새 Evidence ID로 실행한다.
