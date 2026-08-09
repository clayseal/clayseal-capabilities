"""Re-identification: harm defined by the AGGREGATION of authorized reads.

## The gap this closes

Our measurement splits agent harm by what defines it, and four axes were already
characterised (`benchmarks/results/four_axes.md`):

**Target.** The action points somewhere it must not. Scope and binding contain
essentially all of it.

**Volume.** Each action is authorized and correctly targeted and there are far
too many. Velocity contains it, at a bounded blast radius.

**Sequence.** A granted read followed by a granted write of what it read.
`confidentiality.py` contains it per value.

**Content.** The action's *meaning* is the harm. Nobody contains this.

There is a fifth. **Aggregation.** Every read is granted, every target is in
scope, the volume is ordinary, and *no single value is sensitive*. Three
non-sensitive fields - postcode, birth date, sex - identify 87% of the US
population uniquely (Sweeney 2000). The harm is in the combination, and it is
complete the moment the agent holds it: there is no sink, no burst, no
out-of-scope target and no single secret.

Flow control is blind to this by construction. Its whole mechanism is
attributing a value to a sensitive read, and here no read is sensitive, so there
is nothing to taint. Velocity is blind because three reads are not a burst.
Scope is blind because a directory the agent is granted is a directory the agent
is granted. This module is the only rung that can see it.

## Why the obvious mechanism does not work

Count the quasi-identifiers the session has read and escalate at three. Measured
against real tau2 traffic, that flags the identity-verification step of ordinary
banking support - `log_verification(name, address, email, phone, date_of_birth)`
is five quasi-identifiers in a single authorized call, 81 times in the corpus,
and refusing it refuses the job.

Two things fix it, and both are declared rather than inferred.

**Identifiability in bits, not a count of fields.** Each attribute carries its
distinguishing power, log2 of the number of values it separates, and the
combination re-identifies when the total exceeds log2 of the population it is
drawn from. This is Sweeney's result expressed as arithmetic, and it reproduces
her published table: {postcode, birth date, sex} = 31.5 bits against a 28.3-bit
population, uniquely identifying; {city, birth date, sex} = 28.7 bits, marginal,
which is her 53%; {state, birth date, sex} = 21.8 bits, not identifying, which is
her 18% at county level. A count of three cannot tell those apart. Nested
attributes do not double count: postcode already implies city and state, so a
geographic family scores its most specific member rather than the sum.

**Whose attributes they are.** A support session is opened for one authenticated
customer and the mandate carries that customer's *key*, an opaque id established
at authentication. Assembling a re-identifying set for that subject is the task
doing its job. Assembling one for anybody else is the harm. The mandate declares
the subject key, never the subject's attributes, so the policy is disjoint from
the data the check is about and the false-block number is a measurement rather
than a restatement of the policy.

Attributes attach to a subject by *linking*: two observations belong to the same
subject when they share an identifying value. Linking is deliberately restricted
to attributes with enough distinguishing power to justify a join - subject keys,
email, phone, a full name - never to a postcode or a birth date, because joining
on a quasi-identifier is the attack.

## What it cannot do

**It can only link what the calls themselves link.** An attacker who assembles a
subject's attributes across calls that share no identifying value is not caught,
because from inside the authorization layer those calls are about different
people. The attacker joins them out of band, using knowledge the layer does not
have. This is the standing limit and it is measured rather than asserted.

**Identity resolution by quasi-identifier is re-identification by
quasi-identifier.** `find_user_id_by_name_zip(first, last, zip)` is the same
query whether the name is the caller's or a stranger's. The mechanism cannot
separate them and the `resolution_allowance` below is a blast-radius bound, not a
discriminator: it permits the caller to be resolved once and contains the second
stranger onward.

**On the argument side there is nothing to redact.** An agent that supplies a
quasi-identifier as an argument already holds it. Redaction is the right response
on the response side, where the value is arriving; here the response is block or
escalate.
"""
from __future__ import annotations

import math
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# --------------------------------------------------------------------------- #
# The attribute table
# --------------------------------------------------------------------------- #
# `bits` is log2 of the number of values the attribute separates, discounted for
# skew where the raw count overstates it. The numbers are chosen so the table
# reproduces Sweeney's published re-identification rates rather than to taste;
# `tests` pins the three cases that anchor them.
#
# `family` groups attributes that are NESTED, where the specific one implies the
# general. Scoring a family takes its most specific member, so postcode + city +
# state scores 15.3 rather than 33.4. `name` is not nested - a given name and a
# family name are independent - so it sums, capped at what a full name is worth.
#
# `linking` marks an attribute powerful enough to join two observations into one
# subject. A postcode is not on that list, and that is the point: joining on a
# quasi-identifier is the attack, not the defense.


@dataclass(frozen=True)
class Attribute:
    canonical: str
    bits: float
    family: str
    linking: bool = False
    # A direct identifier is sensitive on its own, which is a different and
    # already-solved problem (scope, and `confidentiality.py` for the flow). It
    # anchors a subject but contributes no bits, so this module measures only
    # what the aggregation axis is about: fields that are harmless alone.
    direct: bool = False


_ATTRS: tuple[Attribute, ...] = (
    # Geography, nested from coarse to fine.
    Attribute("country", 3.0, "geo"),
    Attribute("state", 5.6, "geo"),
    Attribute("city", 12.5, "geo"),
    Attribute("postcode", 15.3, "geo"),
    Attribute("street_address", 20.0, "geo"),
    # Date of birth, nested.
    Attribute("birth_year", 6.6, "birth"),
    Attribute("birth_date", 15.2, "birth"),
    # Independent.
    Attribute("sex", 1.0, "sex"),
    Attribute("given_name", 12.0, "name"),
    Attribute("family_name", 12.5, "name"),
    Attribute("full_name", 22.0, "name", linking=True),
    Attribute("occupation", 7.0, "occupation"),
    Attribute("employer", 13.0, "employer"),
    Attribute("income_band", 6.0, "income"),
    # Direct identifiers: anchors only, no bits.
    Attribute("email", 0.0, "direct", linking=True, direct=True),
    Attribute("phone", 0.0, "direct", linking=True, direct=True),
    Attribute("national_id", 0.0, "direct", linking=True, direct=True),
)

ATTRIBUTES: dict[str, Attribute] = {a.canonical: a for a in _ATTRS}

# Families whose members are independent rather than nested, and the cap that
# stops summing them past what the combination is actually worth.
_SUM_FAMILIES: dict[str, float] = {"name": 22.0}

# Field name -> canonical attribute. EXACT names only, never substrings: a
# corpus is full of `theater_name`, `file_name`, `project_name` and `movie_name`,
# and a substring rule turns every one of them into a person's name. Matching
# exactly is conservative in the direction that matters - it misses attributes
# rather than inventing subjects - and an operator adds their own schema's names
# through `field_map`.
DEFAULT_FIELD_MAP: dict[str, str] = {
    "zip": "postcode", "zipcode": "postcode", "zip_code": "postcode",
    "postal_code": "postcode", "postcode": "postcode", "postalcode": "postcode",
    "address": "street_address", "address1": "street_address",
    "address2": "street_address", "street": "street_address",
    "street_address": "street_address", "mailing_address": "street_address",
    "shipping_address": "street_address", "home_address": "street_address",
    "city": "city", "town": "city", "locality": "city",
    "state": "state", "province": "state", "region": "state",
    "country": "country", "nation": "country",
    "date_of_birth": "birth_date", "dob": "birth_date", "birth_date": "birth_date",
    "birthdate": "birth_date", "birthday": "birth_date",
    "birth_year": "birth_year", "year_of_birth": "birth_year", "yob": "birth_year",
    "sex": "sex", "gender": "sex",
    "first_name": "given_name", "given_name": "given_name",
    "firstname": "given_name", "forename": "given_name",
    "last_name": "family_name", "family_name": "family_name",
    "lastname": "family_name", "surname": "family_name",
    "name": "full_name", "full_name": "full_name", "fullname": "full_name",
    "customer_name": "full_name", "person_name": "full_name",
    "patient_name": "full_name", "client_name": "full_name",
    "occupation": "occupation", "job_title": "occupation", "profession": "occupation",
    "employer": "employer", "employer_name": "employer",
    "annual_income": "income_band", "income": "income_band", "salary": "income_band",
    "email": "email", "email_address": "email", "e_mail": "email",
    "phone": "phone", "phone_number": "phone", "telephone": "phone",
    "mobile": "phone", "msisdn": "phone",
    "ssn": "national_id", "national_id": "national_id", "nin": "national_id",
    "passport_number": "national_id", "nhs_number": "national_id",
}

# Argument names that carry the subject's opaque key. What authentication
# establishes, and what a mandate can name without naming any of the subject's
# attributes.
DEFAULT_SUBJECT_KEYS: tuple[str, ...] = (
    "user_id", "customer_id", "account_id", "client_id", "member_id",
    "patient_id", "subject_id", "person_id",
)

_WS = re.compile(r"[^a-z0-9]+")


def _norm(value: Any) -> str:
    return _WS.sub(" ", str(value).strip().lower()).strip()


def _maybe_json(value: Any) -> Any | None:
    """A JSON object or array carried as a string, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text[0] not in "{[":
        return None
    import json

    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def identifiability_bits(attributes: set[str], *,
                         table: Mapping[str, Attribute] | None = None) -> float:
    """Distinguishing power of a set of canonical attributes, in bits.

    Nested families contribute their most specific member; independent families
    sum, capped where the cap is known. Direct identifiers contribute nothing:
    they are sensitive alone and belong to a different rung.
    """
    table = table or ATTRIBUTES
    by_family: dict[str, list[float]] = {}
    for name in attributes:
        attr = table.get(name)
        if attr is None or attr.direct:
            continue
        by_family.setdefault(attr.family, []).append(attr.bits)
    total = 0.0
    for family, values in by_family.items():
        if family in _SUM_FAMILIES:
            total += min(sum(values), _SUM_FAMILIES[family])
        else:
            total += max(values)
    return total


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ReidentificationPolicy:
    """What the mandate declares. Nothing here is inferred at runtime.

    `goal_subjects` are the subject KEYS the sealed goal named - opaque ids
    established at authentication. They are deliberately not the subject's
    attributes: the policy must not contain the data the check is about, or the
    false-block rate would be a restatement of the policy rather than a
    measurement of it.
    """

    # Canonical attributes in force. Empty means the default table.
    quasi_identifiers: tuple[str, ...] = ()
    # Extra field-name -> canonical mappings for the operator's own schema.
    field_map: Mapping[str, str] = field(default_factory=dict)
    # Argument names carrying the subject's opaque key.
    subject_keys: tuple[str, ...] = DEFAULT_SUBJECT_KEYS
    # Subject-key VALUES the sealed goal named.
    goal_subjects: tuple[str, ...] = ()
    # The population the subject is drawn from. The threshold is log2 of it.
    population: int = 330_000_000
    # Bits required above log2(population) before the combination counts as
    # re-identifying. Zero means "expected to be unique".
    margin: float = 0.0
    # Alternative, cruder threshold: escalate at N distinct quasi-identifiers.
    # Present so the naive mechanism can be measured alongside the bits model
    # rather than argued against.
    min_attributes: int | None = None
    # How many subjects the sealed goal did NOT name may be re-identified before
    # the layer refuses. One, in a support deployment, because the caller has to
    # be resolved before their key is known. A blast-radius bound, not a
    # discriminator.
    resolution_allowance: int = 0
    # Tools whose word is taken for an identity association. Empty means any
    # call may link two anchors. Useful where a deployment really does have one
    # authoritative identity tool, and useless where the attacker reuses the
    # session's own lookup tool, which is the case the benchmark measures.
    identity_binding_tools: tuple[str, ...] = ()
    # Anchor attributes a subject may hold exactly one value of. A person has
    # one legal name and one national id, so a call binding a SECOND name to a
    # subject that already has one is asserting something false, and the union
    # is refused rather than the call.
    #
    # This is the fix for anchor poisoning, which the evasion sweep found
    # carrying the whole attack through at 100%: one call naming the goal's own
    # subject key alongside a stranger's name merges the stranger into the
    # authorized subject, after which every attribute of the stranger reads as
    # in scope. It is a race, and it is honest about being one: the attacker
    # who binds a name before the session does still wins. The mandate closes
    # that by declaring the subject's name at authentication, which is where it
    # is already known.
    single_valued_anchors: tuple[str, ...] = ("full_name", "national_id")
    # Whether this policy is switched on at all.
    enabled: bool = False

    @classmethod
    def from_mandate(cls, mandate: Mapping[str, Any] | None) -> "ReidentificationPolicy":
        raw = (mandate or {}).get("reidentification") or {}
        if not raw:
            return cls()
        return cls(
            quasi_identifiers=tuple(str(x) for x in (raw.get("quasi_identifiers") or ())),
            field_map=dict(raw.get("field_map") or {}),
            subject_keys=tuple(str(x) for x in (raw.get("subject_keys")
                                                or DEFAULT_SUBJECT_KEYS)),
            goal_subjects=tuple(str(x) for x in (raw.get("goal_subjects") or ())),
            population=int(raw.get("population") or 330_000_000),
            margin=float(raw.get("margin") or 0.0),
            min_attributes=(int(raw["min_attributes"])
                            if raw.get("min_attributes") is not None else None),
            resolution_allowance=int(raw.get("resolution_allowance") or 0),
            identity_binding_tools=tuple(
                str(x) for x in (raw.get("identity_binding_tools") or ())),
            single_valued_anchors=tuple(
                str(x) for x in (raw.get("single_valued_anchors")
                                 or ("full_name", "national_id"))),
            enabled=True,
        )

    @property
    def active(self) -> bool:
        """Absent policy means no re-identification control, so a mandate
        written before this module behaves exactly as it did."""
        return self.enabled

    @property
    def threshold_bits(self) -> float:
        return math.log2(max(2, self.population)) + self.margin

    def canonical(self, field_name: str) -> str | None:
        name = field_name.strip().lower()
        canon = self.field_map.get(name) or DEFAULT_FIELD_MAP.get(name)
        if canon is None:
            return None
        if self.quasi_identifiers and canon not in self.quasi_identifiers:
            attr = ATTRIBUTES.get(canon)
            if attr is None or not attr.direct:
                return None
        return canon


@dataclass(frozen=True)
class ReidVerdict:
    allowed: bool
    reason: str
    # Canonical attributes this subject would hold after the call.
    attributes: tuple[str, ...] = ()
    bits: float = 0.0
    threshold: float = 0.0
    subject: str | None = None
    # Set when the subject is one the sealed goal named.
    in_scope: bool = False
    # The attribute whose arrival crossed the threshold. On the response side
    # this is what redaction would withhold; on the argument side it is
    # diagnostic only, because the agent already holds the value.
    crossing_attribute: str | None = None


# --------------------------------------------------------------------------- #
# The monitor
# --------------------------------------------------------------------------- #
@dataclass
class ReidentificationMonitor:
    """Per-subject quasi-identifier accumulation over one session.

    Holds no policy of its own; `check` is given one, so the same monitor serves
    a session whose mandate changes under delegation.

    Subjects are the connected components of a graph whose nodes are identifying
    VALUES and whose edges are calls carrying two of them. Components do not
    depend on the order calls arrive in, so neither does whether a session
    crosses the threshold - only which call is the one refused, which is the
    blast radius and is reported as such.
    """

    # Union-find over anchor keys, e.g. ("subject", "c1001"), ("email", "a@b").
    _parent: dict[str, str] = field(default_factory=dict)
    # Component root -> canonical attributes observed for that subject.
    _attrs: dict[str, set[str]] = field(default_factory=dict)
    # Component root -> the anchor keys it holds, so a merge can be refused
    # when it would give one subject two legal names.
    _anchors: dict[str, set[str]] = field(default_factory=dict)
    # Anchor keys of the subjects already spent against the resolution
    # allowance. Stored as keys rather than roots and compared through `_find`,
    # so a later merge cannot make an already-spent subject look new.
    _resolved: list[str] = field(default_factory=list)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    # ----------------------------------------------------------------- #
    # Union-find
    # ----------------------------------------------------------------- #
    def _find(self, key: str) -> str:
        parent = self._parent.setdefault(key, key)
        while parent != key:
            key, parent = parent, self._parent.setdefault(parent, parent)
        return key

    def _union(self, a: str, b: str, single_valued: tuple[str, ...] = ()) -> bool:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return True
        if single_valued:
            held = self._anchors.get(ra, {a}) | self._anchors.get(rb, {b})
            for attr in single_valued:
                values = {k.split(":", 1)[1] for k in held
                          if k.split(":", 1)[0] == attr}
                if len(values) > 1:
                    # Two different names for one subject. The association is
                    # false, so it is not recorded; the call itself is still
                    # judged on its own merits below.
                    return False
        # Deterministic merge direction, so the root does not depend on order.
        lo, hi = (ra, rb) if ra < rb else (rb, ra)
        self._parent[hi] = lo
        merged = self._attrs.pop(hi, set()) | self._attrs.pop(lo, set())
        if merged:
            self._attrs[lo] = merged
        anchors = self._anchors.pop(hi, set()) | self._anchors.pop(lo, set())
        if anchors:
            self._anchors[lo] = anchors
        return True

    # ----------------------------------------------------------------- #
    # Extraction
    # ----------------------------------------------------------------- #
    def _observe_fields(self, payload: Any, policy: ReidentificationPolicy
                        ) -> tuple[dict[str, str], list[str]]:
        """(canonical attribute -> value, anchor keys) for one payload.

        Nested payloads are walked, because a schema that puts the customer
        inside `{"customer": {...}}` is the normal case and a flat scan would
        miss it.
        """
        fields: dict[str, str] = {}
        anchors: list[str] = []

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if isinstance(value, (Mapping, list, tuple, set)):
                        walk(value, depth + 1)
                        continue
                    if value is None or value == "":
                        continue
                    name = str(key).strip().lower()
                    if name in policy.subject_keys:
                        anchors.append(f"subject:{_norm(value)}")
                        continue
                    canon = policy.canonical(name)
                    if canon is None:
                        # Agent frameworks routinely pass a tool's arguments as
                        # a JSON string. Not walking into it hides the subject
                        # key of every such call, which in tau2 banking is the
                        # whole `call_discoverable_agent_tool` surface.
                        nested = _maybe_json(value)
                        if nested is not None:
                            walk(nested, depth + 1)
                        continue
                    fields.setdefault(canon, _norm(value))
                    attr = ATTRIBUTES.get(canon)
                    if attr is not None and attr.linking:
                        anchors.append(f"{canon}:{_norm(value)}")
            elif isinstance(node, (list, tuple, set)):
                for item in node:
                    walk(item, depth + 1)

        walk(payload)

        # A given name and a family name in the same call are a full name, and a
        # full name is what links two observations. Without this the retail
        # shape `find_user_id_by_name_zip(first, last, zip)` anchors on nothing.
        if "full_name" not in fields and "given_name" in fields and "family_name" in fields:
            whole = f"{fields['given_name']} {fields['family_name']}"
            anchors.append(f"full_name:{whole}")
        return fields, anchors

    # ----------------------------------------------------------------- #
    # Deciding
    # ----------------------------------------------------------------- #
    def check(self, *, tool: str, args: Any, policy: ReidentificationPolicy,
              response: Any = None) -> ReidVerdict:
        """May this call add what it adds to what this subject already has?

        `args` and `response` are treated identically: an attribute the agent
        supplies is one it already holds, and an attribute the tool returns is
        one it is about to hold. The corpora carry arguments only, so the
        response path is unexercised by the benchmark and said so there.
        """
        if not policy.active:
            return ReidVerdict(True, "no re-identification policy declared")

        fields, anchors = self._observe_fields(args, policy)
        if response is not None:
            more_fields, more_anchors = self._observe_fields(response, policy)
            for k, v in more_fields.items():
                fields.setdefault(k, v)
            anchors.extend(more_anchors)

        scoring = {k for k in fields
                   if not (k in ATTRIBUTES and ATTRIBUTES[k].direct)}
        if not scoring and not anchors:
            return ReidVerdict(True, "no quasi-identifiers in this call")

        may_link = (not policy.identity_binding_tools
                    or tool in policy.identity_binding_tools)

        with self._lock:
            if anchors:
                ordered = sorted(set(anchors))
                for key in ordered:
                    self._anchors.setdefault(self._find(key), set()).add(key)
                if may_link:
                    for other in ordered[1:]:
                        self._union(ordered[0], other, policy.single_valued_anchors)
                # Sorted rather than field order, so which component a call's
                # attributes land in does not depend on how the caller happened
                # to order its arguments. When every union succeeded this is the
                # one component; when one was refused it is a deterministic pick
                # among the several the call failed to join.
                subject = self._find(ordered[0])
            else:
                # Nothing to link on. The call is its own subject and will never
                # merge with another, which is deterministic and order-free. An
                # attacker who assembles attributes across calls sharing no
                # identifying value is not caught, and that is the standing limit
                # published in the results.
                # Keyed on the VALUES, not the field names: keying on names
                # alone would collapse every stranger this tool was ever asked
                # about into one subject and manufacture a crossing.
                subject = "anon:" + _norm(tool) + ":" + ",".join(
                    f"{k}={fields[k]}" for k in sorted(fields))
                self._find(subject)

            held = set(self._attrs.get(subject, set()))
            projected = held | scoring
            bits = identifiability_bits(projected)
            threshold = policy.threshold_bits
            if policy.min_attributes is not None:
                crossed = len(projected) >= policy.min_attributes
            else:
                crossed = bits >= threshold

            in_scope = any(
                self._find(f"subject:{_norm(g)}") == subject
                for g in policy.goal_subjects
            )

            def _commit() -> None:
                if projected:
                    self._attrs[subject] = projected

            if not crossed or in_scope:
                _commit()
                reason = ("subject named by the sealed goal"
                          if in_scope else
                          f"{bits:.1f} bits, below the {threshold:.1f}-bit "
                          f"re-identification threshold")
                return ReidVerdict(True, reason, tuple(sorted(projected)), bits,
                                   threshold, subject, in_scope)

            spent = {self._find(r) for r in self._resolved}
            if subject in spent:
                _commit()
                return ReidVerdict(
                    True, "subject already resolved under the mandate's allowance",
                    tuple(sorted(projected)), bits, threshold, subject, False)

            if len(spent) < policy.resolution_allowance:
                self._resolved.append(subject)
                _commit()
                return ReidVerdict(
                    True,
                    f"identity resolution {len(spent) + 1} of "
                    f"{policy.resolution_allowance} allowed by the mandate",
                    tuple(sorted(projected)), bits, threshold, subject, False)

            crossing = None
            for name in sorted(scoring):
                if identifiability_bits(projected - {name}) < threshold:
                    crossing = name
                    break
            # A refused call does not join the subject's history: it did not
            # happen, so the agent did not learn it.
            return ReidVerdict(
                False,
                f"would identify a subject the sealed goal did not name: "
                f"{', '.join(sorted(projected))} is {bits:.1f} bits against a "
                f"{threshold:.1f}-bit population",
                tuple(sorted(projected)), bits, threshold, subject, False, crossing)

    # ----------------------------------------------------------------- #
    # Introspection
    # ----------------------------------------------------------------- #
    @property
    def subjects(self) -> dict[str, tuple[str, ...]]:
        with self._lock:
            return {root: tuple(sorted(attrs)) for root, attrs in self._attrs.items()}


# --------------------------------------------------------------------------- #
# Scope: whose accumulator is it
# --------------------------------------------------------------------------- #
@dataclass
class PrincipalReidentificationLedger:
    """One accumulator per PRINCIPAL, spanning every session it authorizes.

    A `ReidentificationMonitor` accumulates over one session, which is the
    scope every aggregate control in this library shipped with first and the
    scope an adversary resets by opening a second conversation. The evasion is
    cheap and specific: link the fragments on a DIRECT identifier. An email
    address is worth zero bits by design - it is sensitive alone and belongs to
    a different rung - so `{email, postcode}` is 15.3 bits and passes, and
    `{email, birth_date}` is 15.2 bits and passes. Within one session the two
    merge into one subject at 30.5 bits and the second is refused. Across two
    sessions, a session-scoped monitor has nothing to merge them with.

    `principal_ledger.py` made this argument for spend and `benchmarks/burst.py`
    made it for rate. It is the same lesson and it applies here unchanged: the
    ledger belongs to the mandate, not to the conversation.

    The cost is real and is measured rather than assumed. A shared accumulator
    merges two subjects that share a name, so a support agent who handles the
    same customer twice in a day carries the first session's attributes into the
    second, and the `resolution_allowance` becomes a per-principal budget rather
    than a per-session one. `benchmarks/reidentification.py --sweep scope`
    reports both sides.
    """

    window_seconds: float = 24 * 60 * 60
    _monitors: dict[str, ReidentificationMonitor] = field(default_factory=dict)
    _opened: dict[str, float] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def monitor(self, principal: str, *, now: float | None = None
                ) -> ReidentificationMonitor:
        """The accumulator for `principal`, aged out after the window.

        A lifetime accumulator eventually refuses all legitimate work, the same
        failure `principal_ledger.py` documents for a ceiling with no window, so
        the accumulation is bounded in time and the bound is declared.
        """
        if not principal:
            raise ValueError("principal is required; defaulting it silently "
                             "reintroduces session scope")
        import time as _time

        stamp = _time.time() if now is None else now
        with self._lock:
            opened = self._opened.get(principal)
            if opened is None or stamp - opened >= self.window_seconds:
                self._monitors[principal] = ReidentificationMonitor()
                self._opened[principal] = stamp
            return self._monitors[principal]


def goal_subjects_from_mandate(mandate: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The subject keys a sealed mandate names.

    Separate from `ReidentificationPolicy.from_mandate` so a caller that builds
    the policy programmatically can still read the authenticated subject out of
    the same trusted place.
    """
    raw = (mandate or {}).get("reidentification") or {}
    return tuple(str(x) for x in (raw.get("goal_subjects") or ()))
