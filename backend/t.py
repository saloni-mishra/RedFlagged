from rules import analyze_rules
tests = [
 ("HI scam", "आपका खाता ब्लॉक हो जाएगा। तुरंत ₹499 का भुगतान करें और ओटीपी साझा करें", "HIGH"),
 ("HI bank warn", "बैंक कभी भी आपसे OTP नहीं मांगता", "LOW"),
 ("HI no fee", "कोई शुल्क जमा न करें। OTP किसी से साझा न करें", "LOW"),
 ("HI safe2", "आपका बैंक सही है; कोई शुल्क जमा न करें, OTP कभी साझा न करें.", "LOW"),
 ("HI UIDAI", "आपका UIDAI खाता निलंबित है। तुरंत ₹999 जमा करें और OTP साझा करें.", "HIGH"),
 ("HI intern", "इंटर्नशिप के लिए आवेदन करें; ₹999 जमा करें और 2 घंटे में काम शुरू करें.", "HIGH"),
 ("HI intern2", "इंटर्नशिप के लिए रजिस्ट्रेशन फीस ₹300 जमा करें, दो घंटे में तुरंत", "HIGH"),
 ("HI customs", "आपके पार्सल पर कस्टम शुल्क ₹2500 है, कृपया भुगतान करें.", "MED+"),
 ("Hinglish", "Aapka account block ho jayega, turant OTP share karein", "HIGH"),
 ("Hinglish pay", "Rs 500 abhi bhejo warna account band", "MED+"),
 ("EN customs", "Your parcel is held at customs. Pay Rs 1250 to upi id test@okaxis within 2 hours or arrest warrant will be issued.", "HIGH"),
 ("EN pay+not", "Pay ₹500 now. Do not ignore this, we know where you live.", "MED+"),
 ("EN blocked", "Your account is blocked. Pay Rs 1000 immediately.", "HIGH"),
 ("EN safe", "Never share your OTP, PIN or password with anyone.", "LOW"),
 ("EN no urgent", "There is no urgent deadline for this message.", "LOW"),
 ("EN job", "Work from home internship, pay registration fee Rs 500 to join", "HIGH"),
 ("URL trap", "Update KYC at http://sbi-kyc-update.top/login now", "HIGH"),
 ("URL ok", "see https://sbi.co.in and https://google.com", "LOW"),
 ("URL fp", "see http://purchase.com/offer http://case.com", "LOW"),
 ("URL uidaia", "https://www.uidaia.gov.in/verify", "MED+"),
 ("bit.ly", "https://bit.ly/abc", "MED+"),
 ("FP abhi", "अभी आता हूँ, खाना खा लिया?", "LOW"),
 ("FP photo", "फोटो साझा करो ना", "LOW"),
 ("FP discount", "₹50 की छूट पाएं, आज ही ऑर्डर करें", "LOW"),
 ("FP plain", "Lunch at 2 tomorrow? Let me know. I know the casino place.", "LOW"),
 ("FP abhi roman", "abhi aata hu", "LOW"),
 ("HI jobfee", "बधाई हो! आपकी प्रोफाइल हमारी कंपनी में 'Data Entry Operator' पद के लिए चुन ली गई है। आपकी सैलरी ₹25,000 प्रति माह होगी। ज्वाइनिंग प्रक्रिया पूरी करने और यूनिफॉर्म/आईडी कार्ड के लिए आपको नीचे दिए गए खाते में ₹1500 सिक्योरिटी फीस जमा करनी होगी, जो पहली सैलरी के साथ वापस आ जाएगी।", "HIGH"),
 ("HI jobfee2", "आप सिलेक्ट हो गए हैं, रजिस्ट्रेशन शुल्क ₹500 जमा करें", "HIGH"),
 ("HI legit job", "आपकी सैलरी ₹25,000 प्रति माह होगी। कृपया सोमवार को ऑफिस आएं।", "LOW"),
 ("HI no-fee job", "हमारी कंपनी कभी भी कोई फीस नहीं लेती। सिक्योरिटी फीस जमा न करें।", "LOW"),
]
rank={"LOW":0,"MEDIUM":1,"HIGH":2}
bad=0
for n,t,exp in tests:
    r=analyze_rules(t); lv=r["risk_level"]
    ok = (lv==exp) if exp in rank else (rank[lv]>=1)
    bad+= not ok
    print(("OK  " if ok else "FAIL"), f"{n:13} {r['rule_score']:3} {lv:6} lang={r['language']} {[b['rule'].split()[0] for b in r['rule_breakdown'] if b['triggered']]}")
print("failures:",bad)
r=analyze_rules(tests[0][1]); print(r["flags"]); print([ (b["rule_hi"],b["explanation"]) for b in r["rule_breakdown"] if b["triggered"]])
r=analyze_rules("Pay Rs 1250 now", lang="hi"); print(r["flags"], r["language"])
