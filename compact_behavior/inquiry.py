"""Reviewed inquiry subjects. A credential, request key or output is never a subject.

The model/command fields below are the entity being queried, per Core and the
selected same-request input. Field names stay scoped to the exact service.
"""
import hashlib
import json


# (canonical field, field on the model). Multiple entries are independent axes.
# Gas exports can carry either bill identifier or subscription code.
ROUTES = {}


def _routes(paths, *fields):
    for path in paths.split():
        ROUTES['Services.' + path] = fields


_routes('v1/WaterBills v1/WaterBillsExport v2/WaterBillsExport', ('WaterBillID', 'Identifier'))
_routes('v1/ElectricBills v1/ElectricBillsDetails v1/ElectricBillsExport v2/ElectricBillsExport v3/ElectricBillsExport',
        ('ElectricityBillID', 'Identifier'))
_routes('v1/GasBills', ('GasBillID', 'Identifier'))
_routes('v2/GasBills', ('ParticipateCode', 'ParticipateCode'))
_routes('v1/GasBillsExport v2/GasBillsExport', ('GasBillID', 'Identifier'), ('ParticipateCode', 'ParticipateCode'))
_routes('v1/PostPackagesStatus v1/PostTrackingExtended', ('TrackingCode', 'TrackingCode'))
_routes('v1/RealEstateContract v2/RealEstateContract', ('TrackingCode', 'TrackingCode'), ('NationalCode', 'NationalCode'))
_routes('v1/BankChequeStatusSayad', ('ChequeNumber', 'ChequeNumber'))
_routes('v1/PostalCodeToAddress', ('PostalCode', 'PostalCode'))
_routes('v1/BankIbanInfo', ('Iban', 'Iban'))
_routes('v2/BankIbanInfo', ('AccountNumber', 'AccountNumber'))
_routes('v3/BankIbanInfo', ('CardNumber', 'CardNumber'))
_routes('v1/NationalCardReceiveTracking', ('BirthCertificateSerialNumber', 'BirthCertificateSerialNumber'))
_routes('v1/SocialSecurityInsuranceElectronicPrescription', ('UnderCoveredNationalID', 'UnderCoveredNationalID'))
_routes('v1/SocialSecurityInsuranceElectronicPrescriptionDetails v2/SocialSecurityInsuranceMedicalPrescriptionDetails',
        ('MedicalPrescriptionID', 'MedicalPrescriptionID'))
_routes('v1/TrafficFinesWithImageInquiryGetImage v2/TrafficFinesImages', ('BillUniqueID', 'BillUniqueID'))
_routes('v1/DrivingAccidents v1/TechnicalExaminationCertificateByVin', ('VIN', 'VIN'))
_routes('v1/DrivingLicenseNegativePoint', ('LicenseNumber', 'LicenseNumber'))
_routes('v1/VehicleThirdPartyInsurance', ('InsuranceUniqueCode', 'InsuranceUniqueCode'))
_routes('v1/MunicipalityPropertySafetyTollBills v1/MunicipalityPropertyTollBills', ('IdentificationCode', 'IdentificationCode'))
_routes('v1/MunicipalityTaxiFaresBills', ('Barcode', 'Barcode'))
_routes('v1/LandLinePhoneBills', ('FixedLineNumber', 'LineNumber'))
_routes('v1/CellPhoneBills v2/CellPhoneMciBillsDetails v1/TopUpProductReserve', ('MobileNumber', 'LineNumber'))
_routes('v1/LandLinePhoneBillsExport v3/LandLinePhoneBillsExport', ('FixedLineNumber', 'FixedLineNumber'))
_routes('v1/LivelihoodInformation v1/SfaraCoupon v1/InsurancePolicies v2/SocialSecurityInsuranceHistory '
        'v3/SocialSecurityInsuranceMedicalCredit v2/SocialSecurityInsuranceMedicalPrescription '
        'v2/SocialSecurityInsuranceRetirementReceipt', ('MobileNumber', 'MobileNumber'))
_routes('v1/DrivingLicenseStatus v1/ExitBanStatus v2/ExitBanStatus v1/JusticeSharesPortfolio '
        'v1/MilitaryCardIssuanceStatus v1/PersonStatus v1/PassportStatus v2/PassportStatus '
        'v1/GovernmentRetirement v1/GovernmentRetirementReceipt v1/VehiclePlateNumbers '
        'v1/EducationalExemption', ('NationalCode', 'NationalCode'))
_routes('v1/CarAnnualTaxBills v1/FreewayTollBills v2/FreewayTollBills v1/FreewayTollBillsDetailed '
        'v1/IdentificationDocumentsStatusCar v1/IdentificationDocumentsStatusMotorcycle '
        'v1/MunicipalityCarAnnualTollBills v1/MunicipalityCarParkTollBills v1/MunicipalityCarTollBills '
        'v1/PlateNumberHistory v1/TechnicalExaminationCertificate v1/TrafficFinesCar '
        'v1/TrafficFinesCarNoDetails v1/TrafficFinesCarTotalDebt v1/TrafficFinesCarWithImage '
        'v1/TrafficFinesMotorcycle v1/TrafficFinesMotorcycleNoDetails v1/TrafficFinesMotorcycleWithImage '
        'v1/TransferTax v1/TransferTaxCar v2/TransferTaxCar v3/TransferTaxCar '
        'v1/TransferTaxMotorcycle v2/TransferTaxMotorcycle v3/TransferTaxMotorcycle '
        'v1/VehicleThirdPartyInsuranceStatus', ('PlateNumber', 'PlateNumber'))

# Only aliases on the particular *reviewed input provider*. For example, a
# completed upload's response may be useful, but its input is not the bill.
PROVIDER_FIELDS = {
    ('Services.v1/WaterBills', 'ClientAyanCoInquiry.WaterBillInquiry'): (('WaterBillID','WaterBillID'),),
    ('Services.v1/GasBills', 'ClientAyanCoInquiry.GasBillInquiry'): (('GasBillID','GasBillID'),),
    ('Services.v1/PostPackagesStatus', 'ClientAyanCoInquiry.PostTrackingInquiry'): (('TrackingCode','PackageNumber'),),
    ('Services.v1/LandLinePhoneBills', 'ClientAyanCoInquiry.FixedLineBillInquiry'): (('FixedLineNumber','FixedLineNumber'),),
    ('Services.v1/LivelihoodInformation', 'ClientAyanCoInquiry.SfaraCouponInquiry'): (('MobileNumber','MobileNumber'),),
    ('Services.v1/SfaraCoupon', 'ClientAyanCoInquiry.SfaraCouponInquiry'): (('MobileNumber','MobileNumber'),),
}
POLICY = 'inquiry_subjects_v1'
NAMES = frozenset(field for fields in (*ROUTES.values(), *PROVIDER_FIELDS.values()) for _, field in fields)


def containers(value):
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, dict):
        yield value
        if isinstance(value.get('Parameters'), dict):
            yield value['Parameters']


def token(value):
    # Keep leading zeros and type. Additional sensitive fields enter AD only as digests.
    if type(value) is str:
        value = value.strip()
        if not value or len(value) > 256:
            return None
    elif type(value) is not int or value.bit_length() > 256:
        return None
    return hashlib.sha256(json.dumps(value, ensure_ascii=False).encode()).hexdigest()


def candidates(value, names):
    found = {}
    for obj in containers(value):
        for field in names:
            if field in obj:
                v = token(obj[field])
                found[field] = v if field not in found or found[field] == v else None
    return found


def subjects(service, api, basis, entry):
    if basis == 'reviewed_same_request_provider':
        fields = PROVIDER_FIELDS.get((service, entry['path']), ())
    elif basis == 'business_parameters' or (basis == 'public_api' and api == service):
        fields = ROUTES[service]
    else:
        return {}
    if entry.get('representation') == 'FEATURES_ONLY_V1':
        found = entry.get('inquiry_candidates')
        if found is None:
            # Pre-policy oversized values retain only typed feature snapshots.
            # Recover an exact reviewed field only at these envelope locations.
            saved = (entry.get('feature_snapshot') or {}).get('targets', {})
            found = {}
            for _, name in fields:
                matches = [v.get('value') for prefix in ('', 'Parameters.')
                           for v in saved.get(prefix + name, [])]
                if matches and all(x == matches[0] and type(x) is type(matches[0]) for x in matches):
                    found[name] = token(matches[0])
    else:
        found = candidates(entry.get('value'), [name for _, name in fields])
    return {axis: found[name] for axis, name in fields if found.get(name)}
