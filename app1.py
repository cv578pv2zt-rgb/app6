"""가족 안심톡 | Python 3.10+
실행: pip install -r requirements.txt && streamlit run app.py
배포: 두 파일을 GitHub에 업로드 → Streamlit Community Cloud → app.py.
QR: 배포된 앱의 HTTPS 주소를 아래 QR 공유 메뉴에 직접 입력하세요.
API 키/DB 불필요. 메시지 링크에 접속하지 않습니다. 규칙 기반 보조 점검이며
사기 확정/안전 보증/악성 URL 실시간 조회를 제공하지 않습니다.
메시지는 배포 서버 메모리에서 처리되고 앱 자체 파일/DB/로그에 저장하지 않습니다.
호스팅 사업자의 데이터 처리 정책은 별도입니다. 민감정보를 지운 뒤 입력하세요.
"""
import re
import io
from urllib.parse import urlsplit
import streamlit as st
import qrcode

RULES = [
 ('송금·선입금 요구', r'송금|입금|이체|안전\s*계좌|보증금|수수료|선입금|대납', '돈을 먼저 보내거나 별도 계좌로 옮기라는 요구는 독립적인 확인이 필요해요.'),
 ('인증·개인정보 요구', r'인증\s*번호|비밀\s*번호|보안\s*카드|주민\s*등록|신분증|OTP|카드\s*번호', '인증번호·비밀번호·신분증을 전달하면 계정이나 금융거래에 악용될 수 있어요.'),
 ('기관·업체 사칭 가능 표현', r'검찰|검사|경찰|금감원|금융감독원|국세청|금융기관|고객센터|카드\s*배송', '기관 이름만으로 실제 발신자를 확인할 수 없어요. 원래 사용하던 공식 앱이나 대표번호로 따로 확인하세요.'),
 ('긴급함·위협 유도', r'즉시|긴급|지금\s*당장|오늘\s*안|체포|구속|압류|계좌\s*정지|법적\s*조치|마감', '시간 압박으로 확인할 여유를 빼앗는 수법일 수 있어요. 정상적인 안내에도 등장하므로 문맥 확인이 필요해요.'),
 ('앱 설치·원격제어 요구', r'설치|원격\s*(?:제어|지원)|apk|보안\s*앱|화면\s*공유', '낯선 앱 설치나 원격제어 허용은 위험해요. 문자 링크로 앱을 설치하지 마세요.'),
 ('가족 사칭 가능 표현', r'엄마|아빠|휴대폰.*(?:고장|분실)|폰.*(?:고장|분실)|번호.*바뀌|대신.*(?:결제|입금)', '가족을 사칭할 수 있어요. 기존에 저장한 전화번호로 직접 통화해 확인하세요.'),
 ('대화·거래 경로 변경', r'오픈\s*채팅|텔레그램|외부\s*(?:링크|결제)|안전\s*결제|직거래.*불가|카톡.*추가', '중고거래 앱 밖의 결제나 별도 대화방 이동 요구는 특히 주의하세요.'),
 ('비밀 유지 요구', r'비밀|알리지\s*마|말하지\s*마|혼자만|보안\s*수사|극비', '주변에 알리지 못하게 하는 요구는 확인을 방해하는 위험 신호예요.'),
 ('보상·환급 유인', r'환급|당첨|지원금|저금리|대출|미납|배송.*(?:실패|주소)|부고|청첩', '돈·대출·배송·경조사를 미끼로 링크 클릭을 유도할 수 있어요. 관련 기관에서 따로 확인하세요.'),
]
STAGES = ['아직 아무것도 안 했어요', '링크를 눌렀어요', '정보를 입력했어요', '돈을 보냈어요']
GUIDES = {
 STAGES[0]: ['답장·송금·링크 클릭·앱 설치를 멈추세요.', '메시지에 적힌 번호가 아니라 기존에 저장한 번호나 공식 앱·홈페이지의 대표번호로 사실을 확인하세요.', '필요하면 메시지·발신번호·시간을 증거로 남긴 뒤 차단·신고하세요.'],
 STAGES[1]: ['해당 페이지를 닫고 추가 입력·파일 다운로드·앱 설치를 하지 마세요. 클릭만으로 감염 여부를 확정할 수는 없어요.', '다운로드·설치·권한 허용 여부를 확인하고, 스미싱·악성앱 상담은 KISA 118로 문의하세요.', '앱 설치나 원격제어가 의심되면 해당 기기를 비행기 모드로 전환하거나 전원을 끄고, 다른 안전한 전화로 상담·신고하세요. 초기화 전 증거 보존 방법도 확인하세요.', '이미 정보를 입력하거나 돈을 보냈다면 해당 상황을 선택해 후속 조치를 확인하세요.'],
 STAGES[2]: ['돈도 보냈다면 아래의 송금 피해 조치를 먼저 진행하세요.', '안전한 다른 기기에서 노출된 계정의 비밀번호를 바꾸고, 같은 비밀번호를 사용하는 계정도 변경하세요. 가능하면 모든 세션을 로그아웃하고 다중 인증을 설정하세요.', '계좌·카드·인증정보를 제공했다면 해당 금융회사 공식 고객센터에 즉시 연락해 이용 정지 등 필요한 보호 조치를 요청하세요.', '신분증 등 개인정보가 노출됐다면 금융감독원 개인정보노출자 사고예방시스템 등록과 명의도용 여부 확인을 검토하세요.'],
 STAGES[3]: ['추가 송금을 즉시 중단하세요. 분석 결과를 기다리지 말고 송금·입금 금융회사 공식 고객센터 또는 경찰 112에 즉시 연락해 피해 신고와 지급정지를 요청하세요.', '이체 내역, 상대 계좌, 대화·문자와 발신번호를 보존하세요. 기기 감염이 의심되면 다른 안전한 전화로 신고하세요.', '금융회사·경찰 안내에 따라 피해구제 신청과 후속 절차를 진행하세요. 지급정지 가능 여부와 환급은 보장되지 않습니다.', '피해금을 찾아주겠다며 선입금·수수료를 요구하는 2차 사기를 주의하세요.'],
}


def analyze(text):
    findings = []
    for title, pattern, reason in RULES:
        hits = list(dict.fromkeys(m.group(0) for m in re.finditer(pattern, text, re.I)))
        if hits:
            findings.append((title, hits[:5], reason))
    urls = re.findall(r'(?:https?://|www\.)[^\s<>\"\u201d]+', text, re.I)
    hosts = []
    for u in urls[:15]:
        try:
            h = urlsplit(u if '://' in u else 'https://' + u).hostname
            if h and h not in hosts:
                hosts.append(h[:200])
        except ValueError:
            pass
    if urls:
        findings.append(('외부 링크 포함', [], '링크를 열거나 진위를 조회하지 않았어요. 표시된 도메인이 그럴듯해도 공식 사이트라는 증거는 아닙니다.'))
    return findings, hosts


def reset():
    st.session_state.clear()


def main():
    st.set_page_config(page_title='가족 안심톡', page_icon='🛡️', layout='centered')
    st.markdown('''<style>
    .block-container{max-width:660px;padding:1.3rem 1rem 2rem;}
    [data-testid="stAppViewContainer"]{background:#f4f7fb;}
    [data-testid="stHeader"]{background:transparent;}
    .hero{text-align:center;padding:12px 0 14px;}
    .hero h1{font-size:2rem;color:#173c47;margin:0;letter-spacing:-1px;}
    .hero p{color:#455b66;font-size:1rem;margin:8px 0;}
    .badge{display:inline-block;background:#d9eee7;color:#18523f;border-radius:20px;padding:5px 12px;font-size:.82rem;}
    textarea,input{font-size:16px!important;}
    .stButton button,.stFormSubmitButton button{min-height:48px;border-radius:12px;font-weight:700;}
    [data-testid="stVerticalBlock"]{gap:.7rem;}
    @media(max-width:600px){.block-container{padding-top:.8rem;}.hero h1{font-size:1.8rem;}}
    </style><div class="hero"><span class="badge">누르기 전에, 보내기 전에</span><h1>🛡️ 가족 안심톡</h1><p>의심 메시지를 살펴보고, 지금 할 일을 확인해요.</p></div>''', unsafe_allow_html=True)
    st.caption('외부 AI 전송 없음 · 앱 자체 기록 저장 없음 · 사기 여부를 확정하는 서비스가 아닙니다.')
    # 상황 안내는 검사 버튼/메시지 입력과 무관하게 즉시 이용 가능합니다.
    stage = st.selectbox('지금 어떤 상황인가요?', STAGES, key='stage')
    if stage == STAGES[3]:
        st.error('송금했다면 점검보다 신고가 먼저입니다. 금융회사 공식 고객센터 또는 경찰 112에 즉시 지급정지를 요청하세요.')
    with st.expander('🚑 지금 해야 할 일', expanded=stage != STAGES[0]):
        for i, step in enumerate(GUIDES[stage], 1):
            st.write(f'{i}. {step}')
        st.markdown('**긴급 피해 신고: 112 · 금융 상담: 1332 · 스미싱·악성앱 상담: 118**')
    with st.form('message_form'):
        text = st.text_area('의심되는 문자·대화를 붙여 넣어 주세요', height=155, max_chars=10000, key='message', placeholder='이름·전화번호·계좌번호·인증번호는 지우고 입력하세요.\n예: 엄마 나 폰 고장났어. 지금 이 계좌로 대신 송금해 줘.')
        submitted = st.form_submit_button('🔎 위험 신호 살펴보기', type='primary', use_container_width=True)
    if submitted:
        st.session_state.pop('result', None)
        if text.strip():
            st.session_state['result'] = (text, analyze(text))
        else:
            st.warning('점검할 메시지를 입력해 주세요. 위 상황별 안내는 입력 없이도 확인할 수 있어요.')
    if 'result' in st.session_state:
        original, (findings, hosts) = st.session_state['result']
        st.subheader('점검 결과')
        st.caption('마지막으로 점검한 메시지 기준 · 규칙 기반 탐지, 확률·안전 등급을 제공하지 않습니다.')
        if findings:
            st.warning(f'확인이 필요한 표현 {len(findings)}종류를 찾았어요. 정상 안내도 탐지될 수 있습니다.')
        else:
            st.info('등록된 위험 표현을 찾지 못했어요. 안전하다는 뜻은 아닙니다. 발신자와 요청 내용을 공식 경로로 확인하세요.')
        for title, hits, reason in findings:
            with st.expander(title, expanded=True):
                if hits:
                    st.text('발견한 표현: ' + ' · '.join(hits))
                st.write(reason)
        if hosts:
            with st.expander('메시지 속 도메인 보기 (접속하지 않음)'):
                for h in hosts:
                    st.code(h, language=None)
                st.caption('링크 자동 클릭을 막기 위해 코드로 표시합니다. 단축 URL 목적지·도메인 소유자·악성 여부는 조회하지 않습니다. URL 인코딩·숨겨진 링크는 놓칠 수 있습니다.')
        st.info('공식 확인: 받은 메시지의 링크·번호는 사용하지 말고, 평소 쓰던 공식 앱이나 직접 확인한 대표번호를 이용하세요. 가족 요청은 기존에 저장된 번호로 직접 통화하세요.')
    st.button('입력·점검 결과 지우기', on_click=reset, use_container_width=True)
    with st.expander('📱 가족에게 앱 QR 공유하기'):
        st.caption('배포 후 주소창의 실제 HTTPS 앱 주소를 입력하세요. QR은 접속 수단이며 가족 전용 접근 제한은 아닙니다.')
        address = st.text_input('배포된 앱 주소', placeholder='https://your-app.streamlit.app', key='share_url', max_chars=500)
        if address:
            try:
                p = urlsplit(address)
                valid = p.scheme == 'https' and bool(p.hostname) and not p.username and not p.password
            except ValueError:
                valid = False
            if valid:
                image = qrcode.make(address)
                buffer = io.BytesIO()
                image.save(buffer, format='PNG')
                st.image(buffer.getvalue(), width=200, caption='가족 안심톡 접속 QR')
                st.download_button('QR 이미지 다운로드', buffer.getvalue(), 'family_safe_qr.png', 'image/png', use_container_width=True)
                st.caption('입력 주소의 실제 배포 여부는 확인하지 않습니다. 공유 전 본인의 주소가 맞는지 확인하세요.')
            else:
                st.warning('로그인 정보가 포함되지 않은 올바른 HTTPS 주소를 입력하세요.')
    with st.expander('안내 · 공식 참고 자료 · 배포 방법'):
        st.markdown('''**꼭 알아두세요**
- 한국어 텍스트의 표현을 정규식으로 찾습니다. 오탐·누락이 있으며 문맥·발신자 진위·신종 사기를 판별하지 못합니다.
- 이미지·음성·통화 분석 및 실시간 악성 URL 조회는 지원하지 않습니다.
- 원문은 현재 세션 메모리에서 처리합니다. 지우기 버튼으로 앱의 입력·결과 상태를 비울 수 있지만 호스팅 인프라까지의 완전 삭제를 보증하지는 않습니다.
- 모바일 중앙 정렬 단일 페이지입니다. 긴 메시지·결과는 읽기 편하도록 스크롤합니다.

**공식 확인 경로**
- [금융감독원 보이스피싱 피해 대응 안내](https://www.fss.or.kr/fss/main/contents.do?menuNo=200365)
- [정부 정책브리핑: 개인정보 유출·보이스피싱 대응](https://www.korea.kr/news/policyNewsView.do?newsId=148973197)
- [개인정보노출자 사고예방시스템](https://pd.fss.or.kr/)
- [명의도용방지서비스](https://www.msafer.or.kr/)

대응 문구 참고 확인일: 2026-11-02. 세부 절차는 해당 기관의 최신 안내를 따르세요.

**배포**
1. GitHub 저장소에 `app.py`, `requirements.txt`를 업로드합니다.
2. Streamlit Community Cloud에서 저장소와 `app.py`를 지정해 배포합니다.
3. 배포 URL을 QR 공유 메뉴에 입력합니다. 별도 API 키는 필요 없습니다.
4. 공개 저장소·Secrets에 가족 개인정보나 실제 의심 메시지를 넣지 마세요.
''')
    st.caption('가족 안심톡 · 의심하고, 멈추고, 공식 경로로 확인하세요.')


if __name__ == '__main__':
    main()
