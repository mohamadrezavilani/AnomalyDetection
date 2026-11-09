"""Explicitly synthetic workflow review scenarios; no production contracts."""
import uuid
from dataclasses import replace

from .privacy import Keys
from .time import parse_time
from .workflows import (DeliveryObservation, ExternalEvent, SelectedEvidence, StateContract,
                        WorkflowState, reconcile_workflows)


def workflow_examples():
    namespace = "synthetic_workflow_demo"
    keys = Keys(b"\x51"*32, b"\x52"*32, "demo_v1")
    tok = lambda domain, value: keys.token(namespace, domain, value)
    ref = lambda value: str(uuid.uuid5(uuid.NAMESPACE_URL, "p24-workflow-demo:"+value))
    at = parse_time("2026-10-20T07:30:00Z").epoch_ns
    sources = [SelectedEvidence(ref(v),namespace,tok("origin",v),at+i*1_000_000_000,at+10_000_000_000)
               for i,v in enumerate(("first","second"))]
    events = [ExternalEvent(ref(v),"synthetic-provider","notification","synthetic-event-id",
        tok("external_event","same-event"),keys.version,"a"*64,"synthetic-schema.1","verified","verified",
        ref("identity:"+v),ref("identity-fact:"+v)) for v in ("first","second")]
    deliveries = [DeliveryObservation(ref(v),"http_accepted",tok("delivery",v),tok("request",v),True,
                                     "synthetic-provider","synthetic-delivery-id") for v in ("first","second")]
    contract = StateContract("synthetic-contract.1",(("pending","pending"),("success","success"),("failure","failure")),
        (("pending","success"),("pending","failure")),("success","failure"),("provider",),
        "synthetic-sequence","synthetic:reviewed-fixture","reviewed")
    first = WorkflowState(ref("first"),tok("workflow","example"),contract.version,"success","provider",
        "accepted","verified","complete",subject_domain="synthetic-bill",subject_token=tok("subject","A"),
        link_assertion_ref=ref("workflow-link:first"),state_fact_ref=ref("state-fact:first"))
    second = replace(first,source_version_id=ref("second"),state_key="failure",subject_token=tok("subject","B"),
        link_assertion_ref=ref("workflow-link:second"),state_fact_ref=ref("state-fact:second"))
    def build(events_, states=()):
        return reconcile_workflows(sources,events_,deliveries,states,namespace=namespace,
            event_cutoff_ns=at+60_000_000_000,knowledge_at_ns=at+60_000_000_000,contracts=(contract,))
    return dict(synthetic=True, production_evidence=False, scenarios=[
        dict(key="redelivery",title_fa="یک رویداد منطقی، دو تحویل",description_fa="دو RequestID برای تحویل مجدد، تعداد رویداد منطقی را دو برابر نمی‌کند. پاسخ HTTP پذیرفته‌شده نتیجهٔ کسب‌وکار را تعیین نمی‌کند.",projection=build(events)),
        dict(key="subjects",title_fa="نتیجه‌های متفاوت برای موضوع‌های یک فرایند",description_fa="موفقیت یک موضوع و شکست موضوع دیگر جدا ثبت می‌شوند؛ نتیجهٔ کل فرایند از آن‌ها ساخته نمی‌شود.",projection=build(events,[first,second])),
        dict(key="revision-conflict",title_fa="محتوای متعارض برای یک شناسهٔ رویداد",description_fa="محتوای متفاوت، بدون مرجع اصلاح معتبر جای نسخهٔ قبلی را نمی‌گیرد.",projection=build([events[0],replace(events[1],content_sha256="b"*64)])),
    ])
