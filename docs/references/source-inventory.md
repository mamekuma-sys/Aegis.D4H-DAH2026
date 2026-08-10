# 원본 자료 인벤토리

기준일: 2026-08-10

| ID | 원본 파일 또는 snapshot | 크기·파일 수 | SHA-256 | Git 정책 |
|---|---|---:|---|---|
| PRELIM-GUIDE | `DAH 예선_안내서.pdf` | 201,795 bytes | `F23CC3F96A1AA2FFBEBB9A46AFD82DBCEC34D72A5342B3EBEAB5E954666770BF` | 원본 커밋 금지 |
| PRELIM-REPORT | `DAH2026_예선보고서_Aegis.0xD4H.pdf` | 2,589,793 bytes | `1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E` | 원본 커밋 금지 |
| FINALS-RULES | `DAH2026_본선운영세칙.pdf` | 384,262 bytes | `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F` | 원본 커밋 금지 |
| FINALS-DAY-NOTE | `DAH2026_본선_당일_진행_안내.md` | 9,019 bytes | `AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E` | 파생 팀 메모, 원본 커밋 금지 |
| SKELETON-EXPLANATION | `DAH2026_스켈레톤코드_상세_설명.md` | 27,110 bytes | `BF1CC690C82605497A03B959B93784663EC6D7DFD9949DCBE9C7151B3C07A6AA` | 파생 팀 메모, 원본 커밋 금지 |
| PRELIM-SOURCE | `DAH2026_소스코드_Aegis.0xD4H/` tree snapshot | 115 files | `62320D2100C4BE70997CE595C8952FE924D8EF17061F8575DA0AB753E58C6402` | 원본 tree 커밋 금지 |
| OFFICIAL-SKELETON | `deploy/` tree snapshot | 34 files | `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE` | 외부 통합 시험장으로 유지 |

## 보관과 접근

- 원본 접근 위치는 Git이 아닌 팀 내부 채널에서 팀장이 공지합니다.
- 자격증명이나 개인 PC 절대경로는 이 문서에 기록하지 않습니다.
- 새로운 버전은 기존 행을 덮어쓰지 않고 별도 행으로 추가합니다.
- 운영세칙과 스켈레톤은 버전 또는 수령일을 함께 기록합니다.

## 2026-08-10 첨부본 검증

- PDF 세 개의 SHA-256은 기존 인벤토리 값과 일치했습니다.
- Markdown 두 개는 운영세칙과 스켈레톤을 설명하는 파생 팀 메모이며 공식 원본으로 취급하지 않습니다.
- 다섯 파일의 보관 위치는 팀 내부 채널에서만 공유하고 이 저장소에는 해시와 논리적 분류만 남깁니다.

## Tree hash 주의사항

`PRELIM-SOURCE` hash에는 snapshot 안의 생성 파일과 캐시도 포함되어 원본 폴더 전체의 동일성을 식별합니다. 본선 코드로 이식할 때는 `.pyc`, `__pycache__`, `output`과 생성 데이터는 복사하지 않습니다.
