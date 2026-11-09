"""Compile exact source-registered role proposals; never inspect runtime secrets.

The Core tree is a read-only reference. Routes absent from this audited input
are not assigned a role by prefix or by inheriting another API version.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
CORE_BUSINESS=set('WalletPayment UserWalletCharge InvoicePayment BillsPayment CnpgPayment UserBasketPayment'.split())
CORE_MANAGEMENT=set('LoginByOTP LoginByUserCredential LoginByGoogle UserSessionsTerminate UserSessionsTerminateAllOthers UserCredentialAdd UserCredentialChangePassword UserCredentialClearPassword UserProfileUpdatePersonalInfo UserProfileUpdateLocation UserProfileUpdateFinancialInfo UserWidgetsSetDefault UserQuickAccessItemsUpdate UserServiceQueryNote UserServiceQueryBookmark UserServiceQueryDelete UserMessageRead UserMessageRemove UserDelete CnpgRemoveCard UserBasketAddBills UserBasketDelete UserBasketDeleteItems AutoPayAddOrUpdateFreewayToll AutoPayDelete AutoPayUpdateStatus NotifyMeAdd UserLogOut'.split())
CORE_SUPPORT=set('DeviceRegister ConfigBasic ConfigBusinessInfo ConfigSearch ConfigService Cities MetricsSurvey MetricsSearch UserSessions UserSessionInfo UserSessionUpdateInfo UserCredentialInfo UserProfile UserQuickAccessItems UserServiceQueries UserServicesRecentlyUsed UserMessages UserWallets UserWalletBalance UserWalletChargeChannels UserTransactions UserVouchers UserSurvey PaymentInfo InvoiceDiscounts InvoiceInfo BillsPaymentChannels BillsInfo UserPublicKey CnpgRequestOtp CnpgGetCardList ShaparakBankListService PhoneNumberValidator Ocr UserInvoicePaymentSummary UserBillsPaymentSummary UserBasketGet UserBasketGetItemCount GetBillServiceName AutoPayGet GetServiceNameListByFeature'.split())
SERVICE_CATALOG_READS=set('TopUpOperators TopUpProducts TopUpOperatorsCharge TopUpOperatorsInternetPackage TopUpProductsCharge TopUpProductsInternetPackage TopUpRoamingInternetPackageProducts TopUpChargeCustomConfig BankIbanInfoPrerequisites'.split())
SERVICE_FOLLOWUPS=set('TopUpPurchaseInfo SfaraCouponGetOrderOtp SfaraCouponGetOrderDetail SocialSecurityInsuranceElectronicPrescriptionDetails SocialSecurityInsuranceMedicalPrescriptionDetails'.split())
PUBLIC_MARKET_SERVICES=set('ExchangeCrypto ExchangeCurrency ExchangeGold'.split())
PUBLIC_HOMEPAGE_AUTOMATIC=set('Weather AirPollution CalendarToday CalendarMonth CalendarReligiousTimes'.split())
PROXY_SUPPORT=set('UploadNewCardOcrImage GetCardOcrResult CarTaxCheckUserRegistrationStatus CarTaxForgetPassword CarTaxRequestOtp TechnicalExaminationCertificateCheckUserRegistrationStatus TechnicalExaminationCertificateRequestOtp CarAnnualTaxGetFixedParametersConfig'.split())
OWNER_AUTOMATIC=set('InvoiceRegister AddUserData GetUserData'.split())


def group_is_owner_public(path):
    return path in {'Public.v1/'+n for n in PUBLIC_MARKET_SERVICES|PUBLIC_HOMEPAGE_AUTOMATIC}


def decision(path,families):
    group,route=path.split('.',1);name=route.rsplit('/',1)[-1]
    if path=='Core.v1/UserWidgetsSetDefault':
        return 'support','unknown',None,'ثبت Widget در Module.Metrics و DataBase.UserWidgetsSetDefault؛ مرحلهٔ کمکی رابط کاربری است، نه اجرای مستقل خدمت. آغاز دستی یا خودکار تعیین نشده است.'
    if group in ('Webhook','Job','JobsQueue','PaymentCallback','PaymentRedirect'):
        return 'system','system_followup','system_followup','پیگیری یا هدایت سیستمیِ عملیات قبلی؛ اقدام مستقل مشتری نیست.'
    if group=='Files':return 'support','unknown',None,'تحویل فایل یا نتیجهٔ موجود؛ به‌تنهایی استعلام تازه یا پرداخت نیست.'
    if group=='Core':
        if name in CORE_BUSINESS:return 'business','unknown',('wallet_funding' if name=='UserWalletCharge' else 'payment_execution'),'اجرای پرداخت یا تأمین موجودی؛ آغاز دستی و نتیجهٔ نهایی مالی از نقش استنتاج نمی‌شود.'
        if name in CORE_MANAGEMENT:return 'user_management','unknown',None,'تغییر حساب، تنظیمات، احراز هویت یا امکانات کاربر؛ دستی‌بودن هنوز نیازمند شاهد است.'
        if name in CORE_SUPPORT:return 'support','unknown',None,'خواندن اطلاعات کمکی، آماده‌سازی دستگاه، فهرست‌ها یا ثبت telemetry؛ عملیات تجاری مستقل نیست.'
    if group=='Ewano':
        if name=='EwanoLogin':return 'user_management','unknown',None,'ورود و احراز هویت در مسیر ایوانو.'
        if name in ('EwanoCreateOrder','EwanoPayment','EwanoBillPayment'):return 'business','unknown','payment_execution','مرحلهٔ سفارش یا اجرای پرداخت ایوانو؛ از استعلام خدمت جدا و با شواهد پرداخت مرتبط است.'
        if name=='EwanoUserBillsPaymentSummary':return 'support','unknown','support_status_lookup','خواندن خلاصهٔ پرداخت‌های قبلی.'
    if group=='Public' and path in {'Public.v1/'+n for n in PUBLIC_MARKET_SERVICES}:
        return 'business','unknown',None,'سرویس اصلی نرخ ارز، طلا یا رمزارز؛ تأیید صریح مالک در 2026-10-27. عمومی‌بودن API یا نامشخص‌بودن آغاز دستی، نقش تجاری را نفی نمی‌کند.'
    if group=='Public' and path in {'Public.v1/'+n for n in PUBLIC_HOMEPAGE_AUTOMATIC}:
        return 'support','confirmed_automatic',None,'فراخوانی خودکار پس‌زمینه هنگام ورود به صفحهٔ اول؛ تأیید صریح مالک در 2026-10-27.'
    if path=='Public.v1/ServiceIconUrls':
        return 'support','unknown',None,'دریافت نشانی آیکون سرویس‌ها برای نمایش رابط کاربری؛ نقش با مسیر دقیق تعیین شده است.'
    if group=='Proxy' and name in PROXY_SUPPORT:
        return 'support','unknown',None,'واسط OCR، تنظیمات یا احراز دسترسیِ خدمت؛ به‌تنهایی استعلام کسب‌وکاری یا اقدام دستی مستقل را ثابت نمی‌کند.'
    if group=='Services':
        if name in OWNER_AUTOMATIC:return 'support','confirmed_automatic','support','عملیات پشتیبان خودکار؛ تأیید صریح مالک سامانه.'
        if name in SERVICE_CATALOG_READS:return 'support','unknown','support_catalog_lookup','فهرست محصولات، اپراتورها، تنظیمات یا پیش‌نیاز خدمت؛ خرید یا استعلام مستقل نیست.'
        if name in SERVICE_FOLLOWUPS:return 'support','unknown','support_status_lookup','خواندن نتیجهٔ قبلی، جزئیات سفارش یا مرحلهٔ تأیید همان خدمت؛ درخواست خام جدا حفظ می‌شود.'
        if path=='Services.v1/TrafficFinesImages':return 'support','unknown','support_status_lookup','نسخهٔ v1 تصویر قبض موجود را می‌خواند؛ با v2 دارای قرارداد صورتحساب/settlement یکسان فرض نمی‌شود.'
        if path in families or path=='Services.v1/CellPhoneBillsDetails' or name in ('TopUpProductPurchaseCharge','TopUpProductPurchaseInternetPackage'):
            return 'business','unknown',None,'اجرای مستقل API خدمت در قرارداد و handler؛ حتی تکرار هدف با RequestID دیگر جداست. دستی‌بودن یا قطعیت مالی تأیید نمی‌شود.'
    return 'unknown','unknown',None,'مسیر در سورس ثبت شده است؛ نقش رفتاری آن هنوز به بررسی اختصاصی نیاز دارد.'


def build(core_root):
    core=Path(core_root).resolve();contracts=core/'WebServices/Contracts'
    families={path:entry for entry in json.loads((ROOT/'catalogs/r6_service_family_proposals.json').read_text()) for path in entry.get('facade_endpoints',[])}
    routes={};source_files={}
    def evidence(path,line):
        name=path.relative_to(core.parent).as_posix()
        source_files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        return dict(file=name,line=line)
    def add(path,refs,method=None):
        role,initiation,semantic,reason=decision(path,families)
        family=families.get(path,{})
        routes[path]=dict(role=role,initiation=initiation,semantic_role=semantic,reason_fa=reason,
            family_id=family.get('family_id'),family_label_fa=family.get('family_label_fa'),
            source_method=method,evidence=refs,authority=('owner_confirmed_role_with_exact_source_route'
                if group_is_owner_public(path) else 'source_registered_proposal_not_manual_initiation_proof'))
    for contract in sorted(contracts.glob('I*.cs')):
        group=contract.stem[1:];text=contract.read_text(encoding='utf-8-sig')
        for match in re.finditer(r'UriTemplate\s*=\s*@?"([^"\r\n]+)"',text):
            uri=match.group(1).split('?',1)[0]
            tail=text[match.end():].split(';',1)[0]+';'
            declaration=re.sub(r'\[[^\]]*\]','',tail)
            method_match=re.search(r'\b(\w+)\s*\([^()]*\)\s*;',declaration)
            method=method_match.group(1) if method_match else None
            refs=[evidence(contract,text[:match.start()].count('\n')+1)]
            implementation=core/'WebServices'/f'{group}.svc.cs'
            if implementation.exists() and method:
                body=implementation.read_text(encoding='utf-8-sig')
                symbol=re.search(r'public\s+[^\r\n]+\b'+re.escape(method)+r'\s*\(',body)
                if symbol:refs.append(evidence(implementation,body[:symbol.start()].count('\n')+1))
            add(group+'.'+uri,refs,method)
    # The logging endpoint can differ from the public transport URI. These are
    # exact literals in the reviewed facade, not arbitrary version inheritance.
    implementation=core/'WebServices/Services.svc.cs';text=implementation.read_text(encoding='utf-8-sig')
    for match in re.finditer(r'"(v\d+/TopUp(?:Operators|Products|ProductPurchase)[A-Za-z]*)"',text):
        path='Services.'+match.group(1)
        if path not in routes:add(path,[evidence(implementation,text[:match.start()].count('\n')+1)])
    for path,name,needle in (('Files.Download','Files.aspx.cs','endpoint: "Download"'),('PaymentRedirect.PaymentRedirect','PaymentRedirect.aspx.cs','endpoint: "PaymentRedirect"'),('PaymentCallback.PaymentCallback','PaymentCallback.aspx.cs','endpoint: "PaymentCallback"')):
        source=core/'Pages'/name;text=source.read_text(encoding='utf-8-sig')
        index=text.find(needle)
        if index<0:raise ValueError('expected_logging_endpoint_not_found:'+path)
        add(path,[evidence(source,text[:index].count('\n')+1)])
    handler_witnesses={
        'Services.v3/ElectricBillsExport':('ElectricBillsExportHandler.cs','v3','Settlement()'),
        'Services.v1/TrafficFinesImages':('TrafficFinesImagesHandler.cs','v1','BillInfoWithCache()'),
        'Services.v2/TrafficFinesImages':('TrafficFinesImagesHandler.cs','v2','Settlement()'),
        'Services.v1/BankIbanInfoPrerequisites':('BankIbanInfoPrerequisitesHandler.cs',None,'ShebaInquiryGetDictionary'),
        'Services.v1/SfaraCouponGetOrderDetail':('SfaraCouponGetOrderDetailHandler.cs',None,'InvoiceStatusEnum.Finalized'),
        'Services.v1/SocialSecurityInsuranceElectronicPrescriptionDetails':('SocialSecurityInsuranceElectronicPrescriptionDetailsHandler.cs',None,'InvoiceStatusEnum.Finalized'),
        'Core.v1/UserSurvey':('UserSurveyHandler.cs',None,'DataBase.UserSurvey'),
        'Core.v1/UserWidgetsSetDefault':('UserWidgetsSetDefaultHandler.cs',None,'DataBase.UserWidgetsSetDefault'),
        'Ewano.v1/EwanoCreateOrder':('EwanoCreateOrderHandler.cs',None,'PaymentRequest()'),
    }
    for route,(filename,version,needle) in handler_witnesses.items():
        candidates=[p for p in core.rglob(filename) if not version or '/'+version+'/' in p.as_posix().lower()]
        if len(candidates)!=1:raise ValueError('handler_witness_ambiguous:'+route)
        handler=candidates[0];text=handler.read_text(encoding='utf-8-sig');index=text.find(needle)
        if index<0:raise ValueError('handler_witness_missing:'+route)
        routes[route]['evidence'].append(evidence(handler,text[:index].count('\n')+1))
    return dict(version='p24-source-service-roles-1',unknown_route_policy='unknown_until_evidenced',
        manual_decisions='preserved_including_explicit_unknown',source_files_sha256=source_files,
        owner_role_confirmations={'date':'2026-10-27','main_market_services':['Public.v1/'+n for n in sorted(PUBLIC_MARKET_SERVICES)],
            'automatic_homepage_calls':['Public.v1/'+n for n in sorted(PUBLIC_HOMEPAGE_AUTOMATIC)],
            'role_does_not_establish_individual_manual_initiation':True},
        routes=dict(sorted(routes.items())))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-root',type=Path,required=True)
    parser.add_argument('--out',type=Path,default=ROOT/'catalogs/viewer_service_roles.json')
    args=parser.parse_args(argv);catalog=build(args.core_root)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status='BUILT',routes=len(catalog['routes']),unknown=sum(x['role']=='unknown' for x in catalog['routes'].values()))))


if __name__=='__main__':main()
