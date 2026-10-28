/**
 * Dictionary for a camelCase hump after a truncated key.
 * A hump counts when it is one of these words, or a light stem of one.
 * Shape alone does not: a random vowel-consonant run stays key material.
 * A code word is not a hump unless it is one of these words.
 *
 * The list is ENABLE1, public domain. docs/hump-words.md records the
 * source, the licence, how the cutoff was chosen, the supplement, and
 * the stemming rules. The hermitdave FrequencyWords
 * list (word content under CC-BY-SA-4.0) and the
 * first20hours/google-10000-english list are not shipped. Do not
 * filter those lists back in.
 *
 * The first 10603 words are every ENABLE1 lemma the code and
 * documentation walk observed, highest frequency first. The last 8
 * words are the supplement, alphabetical.
 */
const HUMP_WORD_TEXT = `
from import the for is in and of if to not as return this with or error class true be that none
all type name an use on no value any get version by it else are see default false file self can
set except object string at module only list will try raise used data should when we new code
has but one returns function number which have array may so typing check copy add values python
without must using result path you other optional key given like assert license join bytes does
base either more provided first options format method out float same pass do case size append
under create call then also future index max than exception make was test length info invalid
match range types warning end where empty into need there some property read its note time text
os specific each lib copyright specified found here after ignore single user while internal re
instead instance interface since support example kind otherwise available before current because
argument expected integer parse details these source write exceptions output valid up input
returned split arguments apache cannot line order remove start been both message always open
raises they whether such equal last supported functions contains don including attribute buffer
map reference replace defined keys pip two multiple names already called encoding annotations
errors objects build items containing core constructor require continue null lower original
based licensed allow following mark ensure parameters context option just particular platform
information mode update required work main print count export find now reason even most passed
request run strings different next log root zero break testing decode full include void avoid
super checking package process yield implied point shape state parameter implementation item
created byte close convert id between purpose maximum implemented language possible reserved var
would deprecated global methods being cache level union compatibility common over bit memory
node undefined uses once too way response right rights standard them within contain part
versions warnings exists want change defaults err files tests unknown handle title block char
requires sequence content directory strict encode allowed conditions what about complete could
raw system failed results load via warn complex their console second long through additional
present back extra old provides vendor mapping skip useful view logging missing sub your cases
declare equivalent group target done extends issues left res sure above added character command
fitness form obtain prefix special terms binary least operation random currently directly raised
link logger many flags issue library public removed works allows ones stream element negative
still usage due how keep local location means protocol timeout behavior del field hash header
initial sorted arrays less let never style connection extend running express generate scalar
strip zip keyword lambda needed basis characters compile our per take correct environment named
status fail resolve script symbol callable client corresponding existing permissions safe
specify calls corporation unless cast double might custom debug docs exports warranties were
windows actual calling flag real release simple those exit filter needs own provide variable
wrap another callback normal zeros server until attributes catch determine operations search sum
checks licenses paths reset supports control define during entry fields verify basic large
private web creates limitation limitations setup sort access examples exist legacy parser pop
setting throw deprecation disable every however later necessary parsed port actually compliance
offset compatible elements headers sets store unsupported absolute below explicitly numeric
record well classes dictionary finally free generated identifier previous width install us
enable governing matches requests something apply bad lines numbers override rather show
algorithm event host modify times along delete positive representing loop clear converted
instances takes axis distribution ignored parent promise contents doc general generic small
stack automatically compare includes infringement itself ret total fails made stop against body
built documentation included properties cause got installed limit position put ref similar
attempt packages requirement wrapper entries fill major normalize nothing insert matching
minimum mod partial place software three around reduce representation top correctly known please
related reshape section creating en generator handler handling modules parts passing thread
alias bar changes cover es repository stored big extension high longer operator pep socket
backwards changed greater integers received requested signature wrong auto column enumerate
final scheme shared upper anything appropriate encoded overflow overrides short space very
application associated closed enabled extract logic op prototype blob date ma pool proxy syntax
codes description dual makes off points precision register subclass await collections considered
help previously supplied table validate chain construct did lists native post wait parametrize
represents round suffix begin floating na trailing others parsing relative unique yet again
fixed meta nested origin send tag writing dimensions explicit extensions force initialize low
side slice written assume best exactly fit likely row save slow configuration connect difference
know math my project domain indicates inside produce requirements resulting abs accept
dependencies expression immediately manager normalized query users according address bound mean
notes pi win chunk dot gets pairs power report returning starts taken whose alternative java
literal modified packaging push reverse wheel adds bug comparison constant developer inputs
matrix nan performance prevent rules spec temporary underlying bits consider depending
determined give larger move outside variables detect effect failure mask readable regular
specifies starting cached desired disabled display expect floor implement installation label
lookup pattern preserve replaced scalars sign therefore things verbose abstract applied look
machine minor together action adding color dependency dimension down hello implements indices
pair perform probably thus treated typed worker execute handled padding reading remaining sent
typically checked compute fallback latest messages multiply properly subclasses wrapped
cryptography descriptor enough exact fix flat indicating iteration processing resolution rich
specifying switch unable unit unsigned won assign groups helper much password prepare
successfully sync amount arbitrary fast identity structure token various commands external
higher inspect making plain repeat resource success suppress abort dispatch features go leading
resolved separate tags writable across addition casting certain certificate condition contiguous
copies extended factory occur simply thrown able bin broadcast compiled constants conversion
half having loaded opts scripts seconds signed sources almost behaviour contained creation
formats further image problem represent select static trace unsafe warranty better collection
entire mismatch preserved retry session step though working distributed doing head indicate
linear square tools transform trying unexpected usually assertion backward child dispatcher
everything feature hashes loads manually occurs ordered reasons rule sha subprocess unlike
accepts broken category choose direct download exec limited network sample smaller trigger
assignment clean copied decoding document duplicate enter events good inner pointer program
references rest scope separated threads throws world appear depends divide escape handles
highest important indent merge nonzero pipe possibly priority relevant render structured third
active assumed beginning defines derived dev ensures flatten fully functionality height
platforms site systems vector warns word columns dims dumps ed happen identical intended mac
models page product regression replacement settings signal specifier align decimal environ
evaluate few generally gives imported loading locations normally redirect shift terminal tree
definition dimensional directories earlier executable faster fetch finalize formatted fragment
gnu individual invoked lock logical patch pending processed resources track alpha comment digest
emit indexing preferred storage utility axes callbacks choice comma configured counter deleted
dim fall happens incorrect internally inverse merchantability overwrite performed pull queue
registered reject selected spaces canonical channel consistent delay drop encountered filled
foundation had hold ignoring insensitive occurred partition primitives prints ravel resize
several tell threading trim whole applies archive converts cross dom expand follows infinity
managed payload permission ready red remote taking unchanged updated account caller care
combination completed concatenate convenience destination interval milliseconds ne omitted
overridden portions separator setter share specification subject transfer transpose ab accepted
background bounds component detected follow going hook hooks looks masked maybe meaning model
prior represented responses reversed runs saved segment twice window words bindings building
calculate causes comes components contributor deal distributions editable execution hex imports
incompatible inherit interpreted keywords libraries little recommended refer sequences slots
temp validation container counts described determines easy enables encoder eye flush forward
iterate mixed offsets older pad purposes remain removes sensitive upon aligned chars constructed
dependent dummy emitted floats initialized net optionally performs progress pure rand recent
series sizes structures subset wraps computed connections decoder ends extras getting links
operators outer pipeline prod rank sense specifically streams subtract truncate accessed
although appended applicable arithmetic authors blue center changing chunks coding connected
detail ex marker neither notice outputs potentially problems provider reg resolver safely
skipping sometimes speed started term aliases allowing ar assumes become come converting
decorator distribute exclude factor handlers implementations invoke lead listener nor pickle
published ratio recursive retrieve thing uniform vary wrapping assigned authentication author
bind blocks candidate digits edge experimental formatting infer leave member pick positional
prefer pretty really registry rows specifiers stable suitable tested threshold truncated weight
attempting behaves caused collect constraints equals fine helpers home ids importing integral
listed printing proper retries serialization service shapes statement template unpack variant
ways aa alignment buffered cleanup combined copying crypto depend depth garbage green hope
inclusive infinite inserted layout maps meth newer produces reader receive records rejected
respectively reuse skipped subsequent upgrade behave chosen circular comments completely
conflict decoded direction dispose equality ever finished followed guaranteed guess hard hide
increasing indexed isolated mapped moved pack promises removing satisfy six turn affect blocking
certificates collected disables division finite four gen goes hint linked loose marked master me
measure mechanism necessarily obtained often opt passes policy polynomial pow produced ranges
regardless seek strides task unused visible writes binding bottom calculated compressed de
detection dump evaluation executed feed flexible generation holds middle percent plus recursion
repeated reports seen sentinel sharp summary tries waiting why acceptable alt approach bugs
caching closing conn embedded fifth frame fuller identifiers independent interpreter lowest
modes nodes portion providing releases renderable scale segments smallest successful tokens
typical vars white advanced algorithms assembly away beta blank broadcasting browser clamped
closes communications diagonal discard expects finder flattened generates globally grid identify
implicit incomplete kept lesser letters locale omit printed remainder resume security sending
separately strategy symbols triggered universal wheels yields allocated boston causing channels
comparisons compression constraint construction controls debugging delimiter dynamic evaluated
exceeds exclusive franklin hit installing instantiate largest letter mainly markup mutable
numerical odd onto primary quote redirects redistribute refers released rename rust serialized
spacing stores stride subtype unavailable virtual accessible agent applying attempts builds
bundle capture clients clip cluster combine critical ef expose formatter frozen increment legal
limits locals marks optimize poly reported resolves respect satisfied schemes seed shows sorting
stripped symmetric terminate whenever yes anyway appears arch automatic box buffers candidates
ceil ciphers clone col completion computing configure cos deep designed determining emitter
expressions fact family forces forms invert matched minimal notation opened ordering pages peer
perhaps pilgrim potential promote protocols reached reads reduced restore secure seems sends
sock span stats styles swap synchronous ticket wise analysis angle ax becomes computes coverage
cycle derive describes duration effects efficient egg ellipsis encryption enumerable executing
fa finish font giving identified indexes inject loader located looking members mime mostly
overlap precedence reduction refs replacing roots stat unlink updates weights addresses arm
assuming asynchronous calculation chunked compiler connecting crash decorate delta detailed
differ disk easier elsewhere engine filtering implementing implicitly incoming indicated
instantiation labels manual merged prerelease recursively replaces satisfies say sec shorter
sleep squeeze steps sup variants verification weak accurate allocate alternate average ba bold
cancel colors compress constructing contributors cookie declaration defining excluded exponent
extracted filters finds getter highlight improve inexact initialization keeping lowercase matter
meant modification party pickling places rec rev selection semantics shall similarly sin
themselves timed translate trusted unpacked vertical alive allocation applications branch coerce
compared converter corresponds cursor degrees developers device dropped duplicates exceeded
exiting far frames hand hi hidden illegal impossible increase issued lang locate
multidimensional nearest overload permitted positions promotion quotes receives retrieved
servers signatures significant slightly treat tricks trimmed watch aborted affects ask children
choices coerced coercion curve definitions diagnostic differs discussion effective enforce
eventually expires failures formed instantiated justify kernel lacks lazy levels multiplication
newly operand operating ops overriding owner patterns permit presence processes projects raising
refresh restriction scaling shell sigma sockets trust unary units unspecified usable workers
writer accessing answer architecture attach attached belong boundary breaking cipher
coefficients combinations commit comparing conflicting conjugate consume coordinates describing
development differences disconnect edges emits environments evaluates excluding exits exported
filling git imaginary inferred installer interfaces iterations magenta magic markers near notify
operate padded parses partially prompt quoted rendering risk sanity scan serialize shown
silently singleton sized slices solution solve streaming tile transport typescript unlikely
views walk age apple avoids beyond builder codecs combining controller conversions credentials
database declarations derivative discarded exited expanded exposed filtered folder frequency
gamma graph history images immutable intent introduced kinds lengths listen mat modern modifying
multipart originally overhead past placed prereleases prevents prog question relies renamed
retain saving schema tab un unset unwrap updating utilities variance verifies who wide adjust
asynchronously caches casts codec covered documents ensuring entirely epoch expressed flip huge
human idea idle implies live man matrices measurement packed performing ping pixel practice
prober products proxies pseudo quality region rely rendered reporting responsible rotate
rounding routine screen shares suite tables team timer verbosity wish yellow ae backed binaries
caught cell chained collector colon colour comp conditional consistency cookies corner dealing
decorators disabling domains dots elapsed ending exponential fulfilled generating glob handshake
ideally immediate keeps layer leak lets locally lost nice optimized prepared primarily profile
publish queued quite recognized rem resolving routines samples scaled sections shortcut shuffle
shutdown simplify situations slower soft strictly swapped synchronously transparent verified
weird wrappers adapted affected agreement ahead arising authorization aware black coefficient
constructors convenient convention correspond covers cyan defensive derivation descriptors
dictionaries downloaded early effectively forced forever hints histogram hosts indicator
inherits integration literals maintain manner mem norm obtaining overwritten powers primitive
props rejects runner serial signals somehow states timeouts transformed transforms vectors
whatever accumulate actions adjacent assignments attempted avoided buffering claim clock
composite computation concrete concurrent confidence conflicts consumed cut digit encodes entity
escaped especially failing fancy fixture guide horizontal isolation iterating malformed mix mm
mutate normalizer owned parents period possibility preference preserves propagate punctuation
reasonable receiving reciprocal reconstruct redirected referenced remains respective rewind sh
slash squared stuff titles tracker turned unfortunately unrecognized validated whereas ad alter
among asymmetric authority behind consecutive day decide deprecate deviation displayed distance
documented drain dynamically effort established exchange expired falling fetched fewer figure
fingerprint fits footer fraction front gone gracefully guard heap hence importer inconsistent
incorrectly indentation initially interpretation invokes locked loops lose loss management media
median multiline nans nature operands pause populate predicate processor prop reflect score semi
shim somewhat spawn star suppressed targets tasks underscore uppercase visit worked accuracy
adapter advance assigning batch canvas cap cat charge clears closest collecting compact
compliant concatenated constructs contract counting declared degree despite destroy destroyed
detector discovered disposable easily encapsulates encrypted exposes fetching finding foreground
fresh friendly fulfills granted identifying indirect inherited interpolation invocation iterates
light likes listeners listening locales machinery manage met mi monitor moves normalization
optimization particularly propagation pub quiet requiring retained reused rotation rounded
safety seem sharing signs silent simulate snapshot spinner strong subclassing subroutine
technically terminated tester think tracking transferable unquote usual wants acquire act
additionally agreed alphabet ambiguous appropriately authenticate bare begins belongs boundaries
careful carriage cased clause commonly companion contexts controlled convolve crop damages
decorated describe disallow discarding distinct downloads downstream equation expensive
externally fragments guarantee hack lazily leads liability liable logged lot meet meson mirror
mock moving mu multiplied narrow opening opposite overlapping parallel people presented probing
problematic rebuild recently renders rid scientific sell sessions singular situation solely
splitting statistics stopped storing succeed supply supporting tail tort transaction tried
triggers verifying advantage alternatively am anchor anymore area bases bash border breaks
browsers cells cleaning closely containers converters coordinate cycles dash descending design
detecting develop differently directive disallowed efficiency enabling essentially establish
estimate extending fitting flow freeze happened holding insertion installs intermediate
intersection italic joined la latter law leaves mappings modifies naming observed occurrence
operates orientation owns panel parsers permutation person pixels ports prefixed protected race
receiver referencing representations resets resized revision searching serve showing simplified
slicing slot sorts stops straight subtraction succeeded succeeds sufficient tan transformation
treats tricky unbound unnecessary unshift varies weighted weighting whom widths algebra
allocator amin analyze anywhere appending bright bypass cancelled collapse communication
complicated confirm confusing consisting continuation cosh decision decodes definitely divisor
draw duplex duplicated endpoint evaluating exceed falls gather geometric grammar greek grow
hashed helps hereby highlighter holders hyphen identifies improved interpret invariant iterated
languages leaks listing lowercased mail mess minutes occurrences optimal palette pat perm
pickled pointing polynomials proceed rate rational recorded reduces reliable reproduce
requesting rewrite scheduled secret selector signing simultaneously sinh specifications spelling
squares startup sublicense subscript substitute suffixes suggestion summed surrogate timing tiny
touch transparency transposed trip unmodified upload validating validity wanted year zone acts
approximation archives ascending asking atomic atomics awaited blocked bother calculating card
catching checker complement concatenation consist contrast counted credential customize defer
deflate density directives dispatches emitting ended er et extracting fake fastest finishes five
fixing foreign fork fractional gauss grey guarantees hierarchy ideal identification indented
individually interaction jar logs lookups matcher medium micro mid minus mismatched missed
modifications mutually noise obvious opaque overloads packet percentile phase piece populated
precise predefined prefixes preparation preserving randomly redundant regarding reload removal
retrieves roll schedule selecting separators soon sparse substantial tells tensor theory
throwing tick transition translated turns valued verbatim xi ability absent accepting
accordingly adjusted aggregate ai alphabetic alphanumeric annotation assertions baseline
broadcasted buggy calculations centre chance cleared coming compares composed computer consumers
contact criteria curl currency cyclic dealings delayed diagnostics discouraged discovery edit el
elliptic em equivalence executes favor fed finalized folders forwarded furnished heading held
highlighting indication infos insecure inserts instantiating interact interactive
interoperability intersect invoking issuer john keyed lack leaving life manages masks material
mimic monotonic month offer opens orient ourselves persistent persons pieces placeholder
preferences preparer promoted propagated qualified redirection repeatedly reserve responsibility
roughly said sampling sensitivity silence statements strange styled swapping symbolic teardown
theme tolerance tool tracked transient triangular triplet tup unaligned uncaught underline
underscores unpacking unwrapped upstream usages variation vice violation waits water accumulated
achieve acquired additions android approximately assemble auxiliary basically blink blur bounded
branches bucket business cad came capable capitalize chrome circle compilation completes
considering consists consumer convolution cost counters cropped days decoration demand desktop
detached dirty disconnected discover divided drive encrypt english entered examine exclusion
expectation explanation extraction fashion fatal fixes fonts forbidden forwarding fractions frag
framework gain generators gradient graphics guides hat he heuristic hexadecimal initiated
intentionally latex leaf libs lies lo locks longest magnitude mangle manipulate mechanisms
modifier modulus mutated negate opposed ordinary outstanding overall ownership pa parenthesis
patching percentage permanent plane play poll pong pooled portable preceding principle
probability protection queried queries rare reach recording reducing relatively relying
replacements representable restricted rotated salt saturation says scoped sees shallow shrink
someone specially specs spline standards statuses submit subtypes thought threaded timeline
timers towards tunnel unstructured unverified vertically aborting absence alone alternatives
animated appends approximate arc art asked asserts asset associate assumption atom banner beware
bias blend bracket brackets bunch capabilities capacity categories chroma circumstances claims
cleaned cols comparator complexity configurations consistently continues contributions covariant
cur curr dates declaring decreasing decrypt deficient deletes deleting deletion deterministic
differentiate digital downloading drawing editor enclosing escapes estimated everywhere excess
exhaustive expecting expiration flushed fold forcing generalized grouped growing hiragana
historically hour impact imply increases incremental inspector inter interesting intrinsic
invalidate keyboard knows lab li lifetime mach macros maintains marking mathematical memo
minimize minute modifiers monkey nesting notifications notified oriented outgoing parentheses
patched peak peek pipelines piscina pol pools prevented prime providers quickly recognize
redirecting registers reinstall rejection remember reshaped resolvers restrict semantic shaped
shorthand shy spin splice spurious stability stripping subscribe substitution subtle sun
supposed tabs tar textual tied tiff traditional translation traverse treatment triple
unconditionally undo unnamed unreachable unreliable varying watcher yanked yielded activate
adaptive additive animation anonymous areas attacks avoiding backing backslash benefit besides
bi bins brace calculates calendar capturing checkout circuit classic cloned collapsed
communicator compilers conform connects consideration contrary correlate cumulative dark darken
decomposition decryption defaulted deliberately denotes deprecations descriptions
differentiation digests discrete dispatched displays dotted dry eagerly echo eggs eigenvalues
elf enclosed entities epsilon erase estimates existence expansion expire fid flattening flop
forget forwards frequencies furthermore gid goal haven helpful horizontally hours hue ignores
increments informational instructions integrate interceptor interest interpolate joining
katakana labeled latency looked manipulating margin markdown masking matters measures mentioned
mimics mirrors mixing mount natural nonce obsolete octet octets oldest opener passwords paste
pasted paused pinned pooling poorly preview protect quadratic radians radius ragged reachable
redirections reductions reflected relationship renderer reorder reply reporter residual
residuals retrying rightmost robust rot rotating rounds rout sanitize satisfying saves searches
selects serializes shard shifting skips smart solved specialized stacked stay stricter
temporarily tilde traces transformer trivial truncating truncation understand understood
undocumented upgrading uts van verb visibility visual wider wire worth zeroth abbreviation
absolutely accesses accidentally accurately activated adopted advised affecting alongside
altered analogous analyzer apparently attaches bail band benchmark bigger broadcasts bundled
busy cab canceled cancellation capsule caption captured carefully caret cent chi choosing
cleanly clipping closure cloud collision colons comparators compiles compound con concurrency
conditioned configures consequently considers constrain consult continuous correction criterion
dead debugger decimals decompress delegate delimited derivatives detach disconnects displaying
disposition dup eager eliminate equations excludes exercise expanding exposing face factors
fairly fitted flushes formatters formula fourth freed great growth guessed highlighted holder
hyphens icon illustrates indefinitely indirectly inheritance initializes initializing interested
interpolators intersects invalidation involved involving linker losing maintained managing
mandatory manifest measured miss modulo multivariate needing negotiation normalizes numerically
oh orange ordinal outdated overlay pandas paragraph parallelism parametric patent pe peps
pictures plot pointers policies presentation press pro probe producing programmatically purely
quad qualifier quantile questions quick quit quotient quoting rad referred regions registration
relating reloaded repetition resemble respond restored role sandbox scanned scenario scheduling
scores selectors semicolon separating serves services setters shaking shalom sharpen sibling
sites spawned spend stale stamp stem sticky streamed strike subnormal subsampling subscribed
subscriptions substituted successive suggest supplying surprising suspend synthetic terminals
throughout toggle tracing traffic trail transferred transmission traversal triangle triples
unauthorized unblock univariate unlimited unmasked unravel vertex vim watched watches worry
wrote zeroes accent achieved activity agree al allocations analyzing annotate annotated arabic
arise aspect bars binomial blanks bogus bootstrap borrowed bot broad bubbles burn cancelable
captures caution cee clamp clearly combines complains confused conjunction corners correctness
corrupted counterpart couple cutoff decay dedicated deeply defaulting deferred delivered
desirable differing dimensionality dispatching distinguish doubles downgrade drops editing
efficiently eight embed endings endpoints enforced entering entropy equivalents escaping evenly
executor existed existent extern extracts fault fired focus forth fulfill fun functional gotten
hang happy hardware hashing health heavy homogeneous hopefully hot hub hypothesis ideographic
inaccurate increased incremented independently inheriting injected innermost inserting
inspection instruction integrated integrations intention interacting intermediary internals
interrupt interrupted inverted jitter jump justification kill koi learn legitimate lighten
linking luminance merely merges minify minimizes mo multiplicative multiplicity multiplier naive
normalizing occurring orders orthogonal overflows overlaps overview overwrites permanently
permutations permute persist pickles pipes plat prepares preprocessing printable production
programming programs progressive propagating purge pythons rarely reaches react recommend
recover recreate redact refuse rep repeats reporters reraise reshaping resizing resolutions
retried retrieval retrieving reveal rollback sampled sea searched secondary settled shadow
shebang shifted shortest shut sides slashes snippet sol solutions south spans spent spinners
stage statistic strategies stretch strips stroke stylize subscribes subscription subscripts
substitutions sugar superclass switching symmetry tagged terminator thereof training translates
triggering truth um unbuffered unnecessarily unordered unregistered unscaled unwanted validates
visited watching wild wishes yourself accounting accumulation ace acquires acquiring adapters
afterwards agents aid aims allowable altogether amplitude anti apparent approximated arbitrarily
architectures arrow asserted assignability assignable asterisk attention augment augmented
availability awaiting baa backtrack backup badge bandwidth became behaved bisect blindly bob
bodies bounding calculus callers capitalized carry central clarity classifier coercible
collisions commas commented compiling comprehensive conforming connector consumption contiguity
contributing conventions corrected correlation corrupt costly country covariance crashes daemon
dashes dealt declares decompression decrease delivery denominator detects differentiated
digitize directed disclaimer disposed dither dodge dos ebb edition eligible emulate enlargement
ephemeral equivalently establishing estimation euro evaluator exhausted exhaustion exotic
explain exporting extremes feedback fills fire flagged flattens flex frequently futures gave
getters globs gray greedy ha hanging heuristics highlights identities importable inch incidental
inclusion indexer inference infers initiates installations insufficient intercept interpolator
intervals introspection kid lat lax legend lenient lightness likelihood lint maker martin
meaningful measurements microseconds miscellaneous mismatches mistake moment movable multinomial
multiplying music mutation nanoseconds natively neutral nonlocal nonnegative normalise north
notably nu numbered numeral observation octal offending okay omitting ongoing organization
originating outcome overloaded paper para parenthesized payloads perceived permissible persisted
persistence picture plaintext pointed preferable preset preventing probers procedure profiles
profiling puts pyramid querying queues ran realm reasonably reconnect referring registrations
rejecting relational relaxed relied reloading replicas replicate reproducible resort respected
restrictions resulted resumes reversing revert revocation sane saturate scanning scenarios
scopes sequential serializing significantly simpler sit skew skippable sliced slope slowest
socks sound spaced speaking sphinx splits spread stash stopping strongly suggested suggestions
surrounding synchronize ta ti tight tint tis tracks trailers traversing treating trick tunneling
turning ultimately unbiased unchecked unclosed unequal uniquely unsorted unstable unusual
upgraded ut variations variety videos viewing wins zipped aba aborts abstracts accumulator adapt
aff affine aggregation albeit alert allocating analyse appearance appendix arrives assigns atop
authorized backs backtracking badly bag basics beforehand began bidirectional bilinear blah
braille brand brightness buff bulk buyer bypassing camel cancels capability casing catalog
centered chaining checkable chooses clipped communicate comparable compose compromise
computations concern concerned concise conditionals consensus conservative considerations
contextual continuing contribute contributes convertible counterclockwise counterparts course
creator cropping cube curly databases deadline deadlock decided decorating defects deferring
definite delays delimiters denied denote denoting dependence descendant destructive devices
difficult dilate directions discards draft dragon dropping duck dumb earliest eff eigenvalue
engines equally erode eta explained extensible extent extractable fin finalization fish flaky
flipped former freedom gap gathered generics geometry governed grained graphs gravity grouping
guards gyp hangul herein histograms historical hits identically ill improperly inadequate
insensitively inspecting instability instructs integrating integrity interactions interceptors
intercepts intern interpolated interpreting introduces invalidated irrelevant iterative kappa
launched leaked leaking lexicographic licensing lie limiting lin listens literally lived
locality localized logically logistic lots machines maintaining manipulation marginally
materials messaging metric midnight mind mismatching mocked mono monotonically months national
navigate navigator negatives neglected negotiated neon nest newton noncentral nonsense noted
notification occupied office official onwards opportunity optimizations outbound outermost pads
partitioned perfect permuted pin placing plural postfix posting prep preparing prohibited
prologue promotes publicly putting pyx quotation radix recipes recipients recognition
reconstructed recoverable recovery redacted redefine referrer regenerated relation relax remap
reordered repack repo resetting resizes responded restart restores reverses revoked rolling
safer sake saw scans segmentation sender ser shortcuts showed siblings signaling signify sim
simplest slave smoke solving somewhere sorter splitter squeezed stand stub stuck styling
substituting sufficiently sums suspended synchronized syntactic tabular tee tel terminates
termination texts thanks theoretically thinks thresholds throughput tiled till told topics
transparently tripped trouble truly tune understands unfortunate uniforms university unload
unmanageable unrelated unwrapping unwraps utilization video violates vulnerability walking wall
went whichever widest widget ye abstraction accessibility accidental acknowledge acting
activating adjustments alist alphabetically ambiguity amounts amp ancestor angular anyone apart
appearing article artificial aside asks attack attribution backslashes balanced bands barrier
behalf behaving behaviors bell book borders braces brew bring bubble bump bundler bypassed cake
cards cascade caveats chains chaos chromium ciphertext classifiers clearing click closer
coalesce coded coherence collation committed complain completeness composition comprehension
computable concept concerns configuring conflicted confusion conjugated consequence
consequential conserve constrained consumes cores cuts dab dance dangerous decides decoders
decreases decrement defect deflated dense deprecating descent designation deviations diagonals
dialect differentiating disconnection disjoint disposes distinction distributor distributors
ditto dividend dividing dog dollar dominant drawn dubious durations ease east eh eliminating
ellipse empirical encoders encrypts enforces enhance enumerated enumeration environmental
essential establishes eviction examining excessive exclusions exclusively exercising experience
exponentiation externals extremely facility fade fan fat favorite fedora fee fingerprints
finishing flare flushing foot forbid forked framing freshly fuzz generalization grades grant
grown guesses gutter harder harmless hatch heavily hierarchical hist hoisted honored imp
implications improves incorporated incrementally inequality inform initiate ins inspired intend
interior interprets introduction intuitive invariants invocations invoker iron isolate issuing
knowledge lanes launch lex lexical locking lognormal luminosity mag malicious mapper masters
maximal meaningless meets merging migrate migration mirrored mirroring mixture modular mon monde
monitoring multipath multiples narrowed narrowing negligence neighbor neighbour newest nil
nonempty nonexistent normed northwest notable nth nulls numbering observations occasionally om
opinion optimise origins orthogonality overdetermined overshoot overwriting packets packing
parity passive pathological payment percentiles periodic physical piping plan planned pointless
population ported positives precisely precisions predictor prefers preprocess prerequisite
preservation primaries primes printer prioritize probabilities probable prompting prompts pulled
purl quadrature quantity quantization queuing quirks quota radii ranks ration recipient
rectangle rectangular redefinition redistribution refused relates releasing reliably remapped
renames renaming repeatability repeating repetitions replacer replica reproduction reps reraised
restrictive resultant retains reusable revealed rewritten ring robin rolled roman rooted route
ruby sans scratch securely seg sentence sentinels served settle seven shadowed sharpening
sharpness shifts shorten shortened similarity simplicity sine sinter slaves slide smooth
snippets sole solo sometime southeast spawning stacks standardized stated stateless stating
statistical straightforward strength structural subclassed subfields subs subsample suites
summarized summation supplies surface swaps targeting tau technique templates ten tends
terminating theta thin tickets tier ties tiles timings tip tot trade trailer transformations
transforming transmitted trellis unambiguously unclear unified unions unquoted unsuccessful
untested unusable unzip upcast uppercased validations varied verifier versus viewed violations
volume wake wave week wherever withdrawn wo worse yay yielding yo abbreviated abbreviating
aboriginal acceptance accordance accounted accounts acknowledged acquisition activation acute
adjusting adjustment adobe adopt advertised aggregated allocates alphabets altering ambient
amongst ancestors anchored annotating annoying arguably arrival aspects associative assumptions
attachments audio augmentations authenticated authenticators authoritative automation averaged
ay backspace balancer bat bed believe belonging bio boom boot breach breadth brought buckets
bypasses camera canceling cant capital caps cardinality carried categorized challenge chop
classical cleans clobber clockwise closures coalescing collapsing collator collects colours
combiner commits community commutative completer completions compositing comprised comprises
concurrently condensed confident confirmation conforms confuse conjugates cons consequences
continuations contra contraction controlling correspondence corruption cosine costs craft crude
cryptographic crystal cubic cup curves customary customization customized dad dagger damage
darker deadlocked deciding decrypts deemed deeper defensively delimit demoted denoted depths
designated destinations destroys destruction die differentiates directionality disconnecting
discriminate disposal distinguished distinguishing dolor downcast earth editors edits einstein
elaborate electron electronic elision emulates emulating encapsulate encounter encountering
encounters encouraged encrypting enforcement enlarging enriched erasing estimating eth evict
examined exclamation explaining exploit explorer expressly extraneous extreme factories
factorization fad fair families feeding film firing firsts fixtures flexibility flight fly focal
food footprint forcibly forgotten foss fragmentation french fruit fulfilling fulfillment
fundamentally gateway ghi glib glyph gothic grab graceful grants granularity greet grows
guidance ham hamming handbook handy harden hearts herm heterogeneous hides highway hung hurt
hyper hypothetical ideograph illustration imagine improvements improving incrementing incurring
indeed indenting indents influences initiator injection insertions inspected instanced instant
intact integrates intelligently intentional intercepted interchange international interpreters
interruption intervening introduce introspect involves joiner jumps junk jurisdiction justified
ka kaiser kernels killing knowing laid lambdas land lane late latitude leftover leg letting lite
literature locator logarithm logarithms longitude loosely looser lossy macro maintainer
maintenance majority managers manipulated mantissa marshal matchers measuring membership mention
meters metrics midpoint mimicking misplaced morsel musical mutations nag naturally navigation
negotiates negotiating noncontiguous nonstandard nontrivial normalised norms nose noting nuclear
numerator obey observe obsoletes offered offers ogham omega omits oops opinionated optical
ordinate organizational originated originates outliers outputting overly owning padder pager
paging paired parametrized partitions pauses peers perfectly periodically periods permissive
permuting perspective phi phonetic photo photographic phrase piecewise pinning pins piped plate
plausible playing poison polling practices preamble precede preceded precomputed predicates
preferring pressed presumably presumed pretend priorities privileged privileges prof profiler
prohibit prone proposed psi quantiles quantities quirk ratios rebuilds recombine recommendation
recompute reducer reexports reflecting reflects regard reloads reordering repeatable replicated
resample resampling reserves resids restoring resumed retaining review revoke rewinding rex
roaming room routed runic safest sat satisfiable sax scales scanner sect semicolons sensible
separates severity shadowing shrinking shuffled signalling silenced silly sink sizing skin
sleeping sliding slight smarter smoothing snap soften solves sourced spectrum spell spelled
spellings spliced splines squeezing stars stick story streamer street studio subitem submission
subscribing subsequently subspace subversion suggests summing suppressing suppression surname
survey survive swallow swallowing switches syn synchronization talk talking tall technical tend
ternary terrible theoretical thorough threw throttle today tone tones tooling touched transfers
transitions translating transmit transposes trapezoid traversed trimming troubleshooting
truncates tunnelling tutorial tweak twelve twisted twitter typos ugly uh ultra unaffected
unassigned unconstrained underlined undetermined unexpectedly unfinished unidirectional
unimplemented unintended unmatched unneeded unpredictable unread unreserved unresolved unrolled
unsatisfied untouched uploading ups urn utilized vertices viable viewer violated visitor
vulnerable warned wed weekday whence wipe wrapt yarn yen zoom abbreviations abnormal abscissa
abusing accents accentuated acknowledgement acknowledgment actively acutance addend admonition
adoption advances advertising advice advisable advise affiliation aforementioned aggressive
agnostic agrees algebraic alignments alleviate ampersand analyser anchors annex anomalies
answers appeared approaches apt arches arena arranged arriving arrows artifact artificially
artistic ascent ass assembled assets assignee atomically attachment attacker augmentation
augments authenticates authorities authorship averaging awkward azure babel backgrounds bails
balancing ball bang battery bear bee beg beneficial benjamin bevel binds binning bloom blowfish
bo bouncing boxes bracketed brighten brightening bringing brown bubbling bullet bumps bun
bundles bus butt button cares carrying catcher catches cautious caveat certification cham
chapter characteristics checkers checkpoint chunking circularity circularly circumvent claimed
classified classify clauses clever clones cloning clubs coalesced coarse coercing coffee colored
comb combo communicating company comparer compensate complicate complies composes compressing
concatenating concatenations conceal conceptually confusingly conic consolidated constituents
constitutes construed consuming containment continued contributed contribution conveniently
conventional convergence convoluted cooked coordinated cope correspondingly council crack
crashed crashing credit crime crossing crypt cue cuneiform cursive customer customise cutoffs
darkening deactivate deadlocks deals deb decompressed decompressing decrements decrypted
deferral defers degenerate delaying delegates delegating delegation deliberate deliver demo
demonstrates denials depended deprecates derives descriptive detaches detailing determination
determinism diacritic diacritical died diffusion dilation disallows disambiguate disassociate
disclosure discrepancy discussed disjunction displacement distances distributive diverges dives
divisible doe drained draws dumped duplication easiest economic egyptian elaborated elide elided
embedding empties emptying encumbered enhanced ensured enterprise enters enumerating envelope
equalization era erasable erased erg erosion erroneous estimator estimators euclidean evicted
evidence evolved evolving exemplary expense expiry exploring exponentially expressible extrude
facilitate facilitates facilities facing factored factoring fallbacks familiar faulty fax feeds
feel feet filed filler finalizes firstly flash flows forcefully fore forgiving formerly framed
freeing frees freshest freshness fro functioning fundamental furthest gallery gender generality
gist glue gnome gold grand granting granular grapheme graphical greatest grids ground growable
hacks hair halt halts halves happening harmful hereunder heritage hertz hes hiding hieroglyphs
highly historic hoist hoisting hole holidays homomorphic honor hundreds ice idempotent
ideographs illustrated immortal impacted imperial improper inactivity inbound inconsistencies
inconsistency inconsistently incur incurred indeterminate indicators inferno infinitely infix
informative infrequently infringed inhibit ink inscriptional inspects instantiations
interactively interestingly interfaced interlace interlaced interleave interned intersected
intersecting intersections interspersed intro introspected invalided invalidity inverses
inversion invisible involve iota irrevocable issuers italics jagged japan jest job jumped kana
kerning keystroke kick kit labelled lacking lam launcher launching layers led legibility
lexically licensor lift lifting lighter lightweight linearly living loaders localize logarithmic
loggers logo lone looping loses losses mailing mandates mangled manipulates manufacture marchen
massage mate mathematics maximize meanings meanwhile mechanical medians menu microphone midi
migrating mild military minimise minimizing mir misdirected mises mistakenly misused miter modi
modifiable mods modulate monotonicity moon morphological mouse movement movie multiband
multiplies multiprocessing mute mutual naked nameless nearly needle needless negated negates
negation negligible negotiate nicely nightly nine nix noisy nonatomic nonlinear nonuniform
northeast notebook notices notifies notwithstanding obligations obscure observer oe oes ons
opted optimisation optimistic optimistically optimizes optionals orchestrator ordinarily
organize organized ortho ought outs overexposed ox packer pahlavi palm pan par parameterize
parsable parties partly pascal patches pats pear penalty perpetual personal pertain petite
phases phone picked pineapple pipelining polish polls poor popular possibilities postal posts
postscript pot pound precondition predecessor predictable preemptive preformatted premature
prematurely pressure principal profits programmatic progression projection promoter promoting
prompted proof proportional prototypically province provisional psalter pseudonym publication
pulls pulse purchase purple purposefully pushed pushes quadruple qualifiers qualify quantifier
quarter queueing racing radial radical rainbow ram ramp ranged rapid raster raveled ravelled
readability rebind receipt recognizable recognizes recomb recombination reconfigure reconnected
redefined refuses refusing regional regularly reimport reinterpret rejections remapping remarks
remembers renegotiation renewal replies repos repositories reproducing resident respecting
respects responds restricts resuming resumption reuses reusing rewrites rho rice rise risks
robot robustness rocket rolls rom rough routes royalty sadly samaritan schedules schemas scoring
scripting scroll secrets seeds seeing seeks sequentially shader shades shading shadows shake
shards sheet shells shields shorthands shrimp shutting si signaled signer simulates simulating
singletons smiley smoothness soap solid sora sortable southwest spades speculative speech speeds
speedup spelt spiral sport spot spreadable squash stacking stamps standing stands staple stapled
statically stays steal stone stretches stretching striding stronger stubs submitted subnet
subprocesses subscriber subscribers subsection subsequence subtracted subtracting subtrahend
successes suffixed suit summarize superfluous superscript supersedes supplementary surfer
surrogates surround surrounded suspected suspends suspiciously swift symmetrize synchronizing
synonym synonyms syntactically synthesized tangent teapot technology telemetry temps tensors
territory thank themes thousands thumbprint tips titling toggled toilet tolerances topmost
topological toss touching toward trademark trademarks trans transactional transformers
translucent transposing trig trims trivia trivially unaltered unbind uncommitted uncommon
uncontrolled uncovered undeclared underexposed undoes undue uneven unitary united unity
universally unloaded unlock unlocked unmanaged unpinned unprivileged unqualified unquoting
unrecoverable unsafely unsent unsized unstack untitled untransformed unwise upside upsilon
uptime useless vanilla vibration voids volumes voluntary vulnerabilities walker wars wasteful
wat watchers weeks west whereby widened wired witch worldwide worst writers ya zap zed zeta aal
abba abbe abed abilities abnormally abrupt abruptly absorbed abuse academic accelerate
acceleration accident accommodate accompanied accumulates accumulating accumulations achieves
acronym activities addendum addressable addressing adjusts administrative advancing advantageous
adventures adversely advertise advisory affix aggregations aggressively ah alarm aligns alleging
allotted allowance alphanumerics alpine alters amalgamated amazon amend ana analysed animal
animations anisotropic anisotropy annoys anon ant antecedent antecedents anticlockwise anyways
apostrophe applicability appropriateness approved approximates aqua aquamarine archaic arrange
artifacts artist asp assess assist associates associations associativity assure asterisks atlas
atoms attestation augmenting authorize automated avail awaiter awaits awoken backlog baguette
bailed baked balance balloon banana bangs bank bas basket bass bastardised batman bazaar beacon
becoming beings bench beneath benefits berlin beside bib bindable binder biome bison bizarre
blacken blazing blending blessing blinking blueprint blurred board bombs bond bonus boo books
bootstrapping boring borrows bort bottleneck bower bread breakdown broader broadest browsing
brute buck bull bumped bundling burrito butter byzantine cabs caldera camellia cancelation
cancelling cans capitalization capped cardinal cargo castable cease cedilla ceiling centripetal
century chances charter chartreuse cheat cheese chess china chocolate chooks circled city clang
clarification classifiable classification classifications clicked clicks climb climbing
clipboard clips closable clue clues clump cob coerces coil cold collapses collides colliding
combinatorial commenting commercial commitment commons communicated compaction competing
compilations complementary complements comply complying composited compositor compressions
comprise computational computationally concealed conceivably concepts conclusion conditionally
conditioning condor conducted cone confirms confuses congestion conjugation connectivity
connectors conscript consent conserved conspicuously constituent constraining consulting
contacting contacts contextually continuity contracted contracting contractions contributory
contrived converge convertor convinces cook cookbook cool copilot coral cork correlates
counterclaim counterintuitive coupled courier courses courtesy crammed crawl crazily credits
crossword cry crying cryptic cuckoo cucumber cull cum cursors custard customizing dandy danger
dangling danish dart datum debt debuggers decaying decipher decreased decreasingly decrypting
dee deepest defend deficiency definitive degas degradation degraded delegator deletions delivers
deltas demanded demonstration deny deployment descendants descendent designates designer desire
destroying desugars determinant deva developed developing diacritics diagnose dialog diamond
dictates differenced digraph dingbats dint directing disagree disagreements disallowing
disappears disassociates disc disclaimed discontinuous discovering discriminable discriminant
discriminants discriminated discriminating discriminators discussing dish dismisses dispatchers
disqualify distinctive distributing dithered divergence divider divides docker door doubly doubt
dove downright downsizing dozens drains driven driver drives dumping durability dutch dynamics
eastern eat ecosystem edited editorial eigenvectors elaboration elaborations elapses elastic
elevate eliding elm embarrassingly eme emitters emphasize empirically employee emulated
encapsulated encipher encircle encompassing endless energy engineering enlarge enormous entirety
epics epilog epsilons equate equivalency eraser ergonomic erroneously essence evaluations evil
exceeding excel excellent exceptional excessively exchanges executables exercises exhibit
expandable expat expectations experienced explode exploits explore explores exponents exporter
exposure extendable extender extensive extractions extrapolation extrema extremum facade faces
facts faintest fear feh fence festival fetches fifteen fifty figures fil finders fires firm
fisher flavor flipping flips flooding floss flowing focused folded followings forbids forks
formal formally formulation fort forwarder fox fragile frameworks friends frustrating fudge
fulfils funds fury fused fuzzy gae gains gal game gamut gems geographic german gesture giftware
girl glide glossary gnat goldenrod gong goodbye goods goodwill goofy grade gradually grammatical
gran grandparent grayed greenlet gross grossly guarded guessing guid guru hall hamburger handed
hands handwritten hangs hardening harm hatchling hazardous headed healed heard heart heartbeat
hell hexagram him ho holdovers holiday homed honeydew honour hood hop hoping horn horribly
hosted house hover humans hundred hunter hybrid hyperbolic hyphenated ideas identifiable
ideograms iff ignorable illustrate illustrating impacts implementer importance importantly
importers impose imprecision impulse inability inaccessible incompatibility incorporates
increasingly indefinite indemnify indemnity indentations indirection indiscriminately
inefficient infeasible inferable inferences inferential infinities inflate influence influenced
infrastructure inheritable injects inlay inputted insists installers institute instruct
instrumentation intends intensity intensive interchangeably interchanged interfere interfering
interleaved interning interpolating intervention intrinsically introducing intuitively invalids
inversely invertible inverts investigation irrespective jam jasper joe johns joins joker judge
junction kanji kex keying khaki killed kills kilometers kingdom kits kitty laboratory labs lag
largely launchers launches lawsuit lay layouts lean leap lectures leeway legally legitimately
leniency letterboxing lev lexicographical liberal licensable likewise lily limb limiter linter
listened listings lit litigation loan localization locators loudly love lovely lowered lowering
lowers luckily lying macintosh mahjong malfunction maliciously mandarin mandated mango mangoes
manifests manufactured maple mappers marc march marshall massaging massive matchable
mathematically maxima meantime measurably megabytes mend mercurial merit mesh messes mib
microsecond midyear mil miles milestones miller million millisecond minded mine mini mint
minuend minuscule misaligned misses misspelling misspelt mistakes misuse mitre mixes mobile
mocha mocking mocks modeled modeling mol moments monitored monitors monster mor motivated
mounted movies multiplications muted nameable namely narrower narrows nasty navy needlessly
negligent neighborhood ness nicer nicest night nobody nod noncharacter noncommercial nonnative
nope normalizable normals notations notifier notifying oak oar observing obtains obviously
occupy od oddity oddly offering offscreen ogam olive omicron opaquer operational optimizing
opting optionality opus orc orchid orphan ours outlier outline outlined outlining overcome
oversupply ow owed oy packaged packs paid painted pairings panic parameterized parental parented
parenthesize parrot participants patchers pausing paw pawn paying peaks pen pend permits
persistently persisting persists pertaining phantom phew pic picking pictographic pictographs
pig pile pink pivot placeholders placement planar planet planning plexus plotting plug plum
polygon pomelo pond ponies popped popping pops populates populating portability possessing
posted postponed powered practical precedes preconditions predicted prediction preflight
prentice presently pressing presume prettier prettify prioritized pristine privates
probabilistic procedures proceeding processable procurement producer prohibits projected prolog
prologues prominent prominently promised promotions propagates proposal proprietary prose
prospective protects prototypes provisioning pruning pseudorandom publishes pulling pulses
pulsing punctuator purged pushing quadrants quadrilateral qualification quantifiable quantizer
quarters quicker quickest quitting quorum rabbit radicals radio randoms rang rat rationale
rationals reaching reacquire reacquired realized reallocate reals reapplies reapplying rebuilt
recalculate recalculation recall recast rechecked reckless reclaimed recombining recompiles
reconnecting reconnection reconstructing reconstruction recovered recreated recur recycle
recycling redefining redistributing redistributions reducible redundantly reentrant reexport
reexposed refines reformed refreshed refreshes regards registering reinterpretation relate
relationships relevance remotely removals renegotiate repacking repair replaceable replayed
replicates replication replications repopulate repopulated representative representatives
reproduced reproduces resembles resend resilient resistant resolvable resorting responder
retention retesting retransmit retransmits revamp reversal reversible reverting reverts
revisions revoking rewinds richer rogue rose rotates routing runners sage sale salmon sampler
sanitized satisfaction sauce scalable scene school scissor scorer scrolled scrolling secrecy
secs sectioned sel semantically sensibly sentences separable separation sepia seriously serving
sever severed shaders shark sharpened shaw shelf shims ships shoe shopping shortening shot
shrinks sieve signifies silver simplifications simplifies simplifying sing sip skat sketch ski
slate slept slicer sloppy slowdown smile snapshots snow solar solver someday sophisticated
sounds sourceless spa spacer sparkling spatial spawns speak specials species specificity
specifics speculation speedups spencer spirals spit spreads spring squaring squid squiggle
stacker staging stalls stamping statics statistician stencil sticking stock stolen stoppage
stopper strang stray stress stringent structurally student stylized subheading submits
submitting subparts subroutines subsets substantially subtitle subtractions subtracts
successively successor successors succinct suffice suggesting suited summarization summations
supe superior superscripts supersede supplement supplemental supplements suppresses surfaced
surfaces surnames surprise surprises suspension suspicious switched syllabary syllabics
syllables synced syncs synth synthesize systemics tabulate tack tacked tailored tale tallied
tampered tang tap targeted tea teal telephone telling temporal temporaries tent territories
terse testability texture textures texturing thinking thistle thorn thousand throttling thumb
thumbnail thy ticketing ticks tidier tidy tiger tightened tiling tilted tolerant tomato ton took
topology torch torque torrent totality totally touches traditionally trampoline transceiver
transcendental transformable transitional transitive transmits transpositions trapezoidal trees
triangles trigonometry trinary triplets tripping tristate trumps trusts tunneled tunnelled
turquoise turtle tweaks twenty twist typo typographic unallocated unbounded unbuildable uncalled
uncertain uncertainty uncollected unconditional underlies undesirable undesired undoing undone
unevenly unfiltered uniformly unintentional unlabeled unlinked unlinking unmask unmeasurable
unpacker unpacks unparented unpick unpleasant unprintable unprocessed unprotected unquotes
unreported unsets unsetting unsuitable unverifiable unweighted upcasting upfront uploaded
uploads upward usability utilise utilize utopia vagaries variances variates velocity vera verbal
verbs vibrate vibrations viewable violet visibilities vision visiting visitors visits
visualization visualized volatile vowel waived wakes walks wanting waste watchable weaker wedge
weekdays weekend weighing weirder welcome western wheat whilst whiten wholesale whoops widely
widen widening wind winding wink winner wiping witness witnesses wolfram workshop wow writ
wrongly xerox yahoo yang yearly years zebra zeroed zig zombie abacus abide abridged abscissae
absorbs absurdly accelerated accentuation accommodates accommodation accomplished achieving
acknowledges acknowledgments acorn acrobatics activates actors actuator adapting adder adequate
adequately adheres adhesive adjacency administrator admission admittedly admitting admonitions
ado adopting ads adult advantages adversary adverse aerial aesthetic affinity afresh afterward
ag ages aggregating agreements aha aids aim aiming airplane akin alas album alchemical alembic
aleph alfa algorithmic alien alike alleged alliance allocatable alloy alphabetical als
alternates alternation altitude amazing ambulance amended amid amphora amplification amulet
anaconda analog analogously analogue analogy analyses analytic analytical analyzed ancient angel
anger angry anguished animate anime anna announced announcement announcing answered antenna
anticipated antiderivative antitrust anxious anyplace anytime apostrophes apples appreciate
approves approximating approximations arcane archetype architectural arcsine arctangent ares
argued aria arises armor armored armoured arrangements arrived articles articulated arts artwork
ascension assembler assembling assistance assistant assisted association assorted assurance
astonished astronaut asymmetry asymptote asymptotically athletic att attaching attain attributed
audience audios audit august authentic authenticating authenticator authorizes automating
automobile autonomous autumn ava averages avocado avoidance aw awa award awl axe azimuth baby
backdrop backgrounding backhand backpack backspacing bacon badger badminton bagel baggage bags
bald ballet ballot ballpoint bamboo bananas bandage banded banjo banknote barber bargain barrel
baseball basing basketball batched batches batching bath bathtub beach beads beaming bearded
beating beautiful beer beers beetle beginner begun beige bellhop bells benchmarks berry beverage
biased biceps bicycle bicycles bicyclist biggest biggie bike biking bikini bill billed billing
billy binned bint biohazard bird birthday bis bisque bites blacklist blacklisted blame bleed
blitz bloat blobs blocker blond blood blossom blowing blush boa boar boards boat bobby bod
boiler bolivia bolt bomb bone bones boogie boohoo bookends bookkeeping bookmark booting borough
boss bottle bottomed bounce bounty bouquet bow bowels bowing bowl bowling boxed boxing boy brain
branching branded brazil breakage breaker breast brevity brick bride bridge brief briefcase
briefs brings bro broadening broccoli broke brokenness broom bubbled budget buffalo buildable
builders buildings bulb bulletin bulls bumping bundlers bunny burden burritos burst busboy bust
busting busts butterfly buttons buy cabinet cableway cactus cadet calm cameras camping canary
cancer candle candy cane canned canoe canon cape captions car carbon carbonated cared carets
carousel carp carr carrot cart cartwheeling cascading castle categorize cater cats causality
cayman cede centers centos centralize centralized cents ceremony certainly cessation chad chair
changeable channeling chaotic chapel chapters characteristic characterized chart chartered
charts chat checkered cheetah chequered cherries cherry chestnut chick chicken chile chime
chipmunk chips choke chooser chopping chopsticks chose chrominance chronological church
cigarette cinema cinematic circuits circumference circumflex circumscribes circumstance
circumvented circumventing circumvention circus cisco cite cityscape clap clapper clapping clash
clashes classed clay cleaner cleanest clearer clinking clipper clobbered clocks clog closeness
closet clothes clover clown club clumps clumsy clunky clustered clusters clutch clutter coaster
coat cocktail coconut cocos cod codesign coercive coffin cog coherent collate collated
collectable collectively collide collided collider collie colorful coloring colorize colorless
comal combinable combinatorially comet commitments communal commutation compacted comparative
comparers compass compensated compete competent complaining complexes complier composing
compressible compressor comps compulsory computers concatenates concealment conceptual
concerning conclude concretely conduct confetti confidences confidential confirming conflated
conflictual conformance confounded confronted congo congratulations conics conjugating
consecutively consented consequent conservation conservatively conserves conserving considerably
consoles consolidate consolidates constitute constrains constructions consulted consumable
contacted containerised contaminate contiguities continuously contour contradict contradictory
controllable controversial converges conversely convey conveyance convince convolutions cooking
coombs coordinating cop copyrights corder corked corn cornflower corrections corrects cortex
cosines cosmetic costa costumed couch countries covert cow cowboy crab cracked cracker crafted
crap crappy crawling crayon crazy cream creative creators crept crescent cricket crimson crisp
criticality croc crocodile croissant crops crore crossbones crossed crown crucial crumble
crystallized cubically cues culpa culprit cult cumulatively cupcake cupcakes cupid curated cured
curling curry curving customarily customers customs cutting cycling cyclone cylinder cypher
cyprus daemonic daemons dag dancer dancers dancing dashing deactivates deaf decays deceleration
decent decibel decibels deciduous deciphered decisions declarative declined decompose decomposed
decompositions decorates decorative decremented decrepit deduce deducted deer defective
deferrals deficiencies definiteness deflating defunct degrades delegated delegations delimits
delineated delist demanding demands demonstrate demote den denial department departure deploy
deployed derelict deriver deriving deselect deselected desert deserve designate designator desk
destruct desugar detectable detections detective detectors determinants determinist devel
deviate deviates devs dharma diaeresis diagnosing diagnosis diagonalized dialogs diameter
diamonds dice dictate dictating dieresis dies differentiable difficulty diffuse dig digester
digging digitalized dimmed dimming dinosaurs director directs dis disambiguating disappear
disappearance disappeared disappointed disassemble disassembling disassociated disaster
discharging disclaim disclaimers disclaims disclose discontinued discontinuities discontinuity
discord discount discourage discoverable discretion discuss discussions disjointed disjunct
disks disposables dispute disregard disregarding disrupt disruptive dissemination distant
distinguishable distinguishes distorter distortion district disturb disturbed disturbing ditch
dive diversion diversity dividers diving divisions divisors dizzy doable doctor documenting
dodger doggie dolls dolphin domino dotting doubled doughnut downloadable downscaled downside
downwards drafting drafts drag dragged dragons draining dramatically drastically drawback dress
drift drink dromedary drooling droplet droplets drum duel dug dumpling duplicating dups durian
dusk duty dynastic eagers eagle ear earl ears easing eating eats echoing educated effecting
effectiveness eggplant eigenvector eighteen eights eject elapse elect electric elephant elevated
elevation elevations eleven eliminates elixir ellipses ellipsoid els embeds emblem emirates
emission emphasis emphasized employ employed emptied ems emulation enciphered encipherment
encircled enclosure encourages encumber endorse endorsed endorsement enforceability enforceable
enforcing eng engage engineer enhancement enhancements enjoy enrich entitled enumerator
enveloped epact eponymous equalise equalities equalizers equatorial equipment ere ergonomics
errant errs esoteric establishment estoppel ether evergreen everyone evicting evictions evolve
ewe exceedingly excepting excepts exchanging exclusivity executions exercised exercitation
exhaust exhaustively exhaustiveness exhibiting existential expander expansions expenses
experiencing expiring explanations exploding exploitable exploited exploration expressing
expressionless expressive extempore extensively exterior extinguisher extractor exuberant
eyebrow eyeglasses eyes facet facets factorial factorized faint fairest fairy faker falafel
fallen falsely fantom farmer faults favours fearful feasible feat feats featured federated
feeling feels fees fem female fencing fennel ferry fetcher fiction fiddled fiddly fig figuring
filer filly finalizing findings finer finger fingers fink fins fir firebrick firecracker
firefighter fireworks fishing fist fixable flake flamingo flashes flashlight flavours flawed
fledged fleshed flexed flipper flit flood floppy flops flour flower flub fluid fluttering flying
fog foggy folding fool fooled fools football footers footprints foremost forge forgetting
forgiven formalize formalized forming formulas fortify fortunately fortune forum fou founded
fountain fragmented frags freaking freedman freeform freely freeman freezes frenzy fretting
fried friendlier friendliness fries frog frown frowning fruity frustrated fuchsia fuel fuji
fullest functionalities funeral funky funny fuse fuses fuss futhark gab gained gaining gambia
games garden garlic gas gatherer gathering gathers gauge gawk gear gem generalised generalize
generalizes generations generative genie gentoo geographical geophysical geophysics gest
gesturing gettable gherkin ghost gib gibberish gibbous gift giraffe glance glass glasses gleam
gleaned globe glove gloves glowing glyphs goals goat gobble gobbles goblin godly goggles golden
golf golfer golfing goo goodman gopher gorilla govern governs grabs graciously grad gradual
graduation graft gram grapes graphemes graphic graphically graphing grave greatly greedily
greeting grenade grenadines greyed grimacing grin grinning groovy groupings guardsman guernsey
guesswork guinea guitar gun guns hah haiku haircut haired hairy haj halfway halo halting halved
hammer hammering hamster handbag handball handful handlebars handyman hant haptic hardened
hardly hardwired hare hatched hatching haystack hazard headline headphone headphones heads
headsets hear hearing heather hedgehog heel heeled heh heights helicopter helm helmet helping
her herb hereafter hetero hibiscus hierarch hierarchies hieroglyph highlighters hiking hinting
hippopotamus his hitting hm hmm hockey hoists honest honestly honey honeybee hong honorific
honoring honoured honours hops horizontals horned horns horse hospital hotel hourglass
householder houses hovers hugging hump hurts hushed hybris hydrate hydrogen hyphenate hypo icons
idiom idiomatic ilia illogical imaging imitates immortalized immune immunities impending
implementers implementors implication implying importation imposed imposes imprecise impression
improbable impure inaccuracies inactive inadvertent inadvertently inappropriate inappropriately
incantation includible inclusions inclusively inconclusive incurs indenter independence indigo
induce induced ineffective inert inevitable inexpensive inexperience infields influencing
informations informs infringe infringing inherently initials initiating inkpot inn innocent
inquire inquired insecurely inset insights insignificant instantiates institution instruments
intellectual intending interacted interacts interchangeable interference interferes interim
interleaves intermediates interpolates interpretations interrobang intersperse intractable
introductory invader invalidates invalidating invalidations invariably inverting investigate
invisibility involuntary ires ironically irrational irregular island islands isle isolating
issuance iteratively ivory jack jade jag jags jasmin jeans jersey jiffies jigsaw jo jordan josh
journal journals joy joystick judged judicious juggling kaf kangaroo kebab keeling keepable
kendo keyset keystrokes kicks kif killer killers kimono kindly kings kiss kissing kitchen kite
kiwi knee kneeling knife knob knobs koala koto kumquat lacrosse lady lagging lakh lamp lands
landscape lantern lap laptop largish laser lasso latent laughing lavender lawfully laws lawyer
laying leader leaders leafy leakage lecture ledger leftovers legible lemon lends leone leopard
leverage leveraging levitating liberally liberty libra licensee licensees licensors lid lifter
ligature ligatures lightbulb lighting lightning limbo lime limiters linen liner linger linters
lion lips lipstick liquid lis lisp literary literate litter littering lizard llama loanwords
lobe lobster locates locomotive logos lollipop longs looped loosen looseness lop lops lorry
lotion lotus loud loudest loudspeaker lozenge luau luggage lum macho macron mad mage magically
magnet magnification magnifying magnitudes mailbox mainstay maintainers majesty mako male mall
mandrake mangos manifestation manifested manipulations mans mantelpiece mantissas manufacturer
manufacturing mar markings markups maroon marquee martial mason masquerading masques mass maths
maximizes maximums mayan meat mechanic med medal mediation medical meeting megabyte megaphone
melon men menace menorah mentioning mentions meow merchant merger meridians mermaid merman
messing messy meteorologist meter methodology meths metro mew mho microbe microphones micros
microscope midpoints migrations mike milk milky millionth mim mimicked mimicker mines minibus
minim minima minimally minimises minimization minimized minimums misaligning misalignment
misbehave miscalculation mishandle mishandled misleading misleadingly misshaped misspelled
mistaken misty mitigate mnemonic moccasin modal modelled moderately modularized modulation mojo
mom monaural money moneybag monkeys monocle monorail monte monthly moo mop moral moreover
morocco morphology mortar mos mosque mosquito mother motion motivate motivation motor motorcycle
motorized motorway mountable mountain mountains mounter mounting mounts mouth moveable mover
muck mug mugs multichannel multilingual multipage multiplex multiplexed multistep mum murphy
muscle mushroom mutates mutating myself nab nail nanosecond nastiness nations natives nauseated
navigated navigating nearby neat necessitating necktie needles negating negatively negotiations
neigh neighboring neighbors neighbouring neighbours nerd networking nevertheless news newspaper
newspeak nib nibble nibbles nickname nightmare nilled nim nimrod ninja ninth nisi nit nom
nomenclature nominal nominally nominated noncommutative nondeterministic nonequivalent nonet
nonparametric nonsensical nonstructured noo noon normalises normalising normality normalizations
normative northern notch notepad notion notionally notoriously novel nudge nulled numb numerals
numerous nun nus nut obeys objective obligation oblivious observable observably obsoleted
occasional occupies ocean octave octaves octopus oddities odist officer officially offs ogre oil
oka oldstyle omission omissions oncoming oneiric onion opacity openers operated optimising
optimum oracle oranges orangutan orb orchestra orderly ordinals ordinates ores organizations
orients originals originate origination ornament ornamental orphans orthodox orthonormal
oscillate oscillation oscillator otter ottoman outbox outcomes outlive outlying outmost outrows
outset outsize outstride outweighs overdue overestimate overestimates overflowed overheads
overlaid overlapped overloading overran oversized ovolo owl owlish owners oxidizer oyster
pacific paddle pain paint paintbrush pairing pal pale palettes palms panama pancakes panda pane
panels panning pants pap papers parallels parameterization parametrization parametrizations
parametrizing park parking parliament participant participate participating participation
particle partitioning partway partying pas passenger passer passport pastie pasting patcher
patents pathologically pay payer payments peace peach peacock peaking peanuts pedantic
pedestrians peg pencil pended penguin pensive penultimate pepper percentages percents percolate
performances permissively permitting perpendicular perry persevere persevering personality
phones photos pht physicists picker picks pickup pie piglet pike pill pilot pinch pinching pine
pings pinyin pipelined pips pirate pistol pitch pizza placements planing plans plats playback
played player playground plays pleading plumbing pod poetry pole police polled polluted
polluting pollution polo pony poodle pooh poop popcorn popover popper popularity portrait posh
positionally positioned positioning possessed postbox poster postpone potable potato pouch
poultry pounds pouting powerful practicable pray prayer precaution precedent precludes
precompute predate predecessors predefine predetermined predict predictability preempted
preemptively prefacing preferably prefilled prefixing pregnant preliminary prelude premise
premodified preprocessor presenting presents preserver presets presses presumes pretends
prettifies pretzel prevails previews price primality primer prince princess principals
prioritizes prioritizing privacy privation privilege probabilists probes proceeds processors
productions productive programmer progresses progressively prohibition projector prolate prom
promotable promoters pronounce proposals proposes protector prototyping provision provisions
provoke provoked prune publications publicity publisher pubs puck pug pump punch punitive puppet
purchaser purging purposely purse pusher pushpin pya quant quartz quaternary quaternion
questionable quietly quiz quotas quotations raccoon racehorse racket racquet radian radiance
radioactive rage rail railway rain raiser rake ramps ranked ranking rarest rated rates rating
raveling ravelling ravels ray razor reactivate reactor readies readily readiness reallocates
reallocation reap reaped reappearance reappears reasoning reassemble reassigned reb rebalancing
rebinds rebound rebuilding recalled receivers reception reciprocals reclamation reclassify
recognise recognised recognizing recommends recompile recompiled recompiling reconfigures
reconsider recordable recorder recovering recovers recreation rectangles rectifies redaction
redefinitions redistributed redo redone redraw reds reducers redundancy reenter reentering
referent refill refine refined reflection reflectors reflexive reformatted reformatting
refreshing refusal refuted regarded regenerate regents registries regressions regularized
regulated rehash rehydrate rehydrated rei reindex reindexed reinstalled reinstalls reinstate
reinstatement reinstates reinterpreted reinvent relations relativity relaunch relaxing relay
reliance relieved relinquish relinquishes remade remainders remedies remedying reminder remotes
removable renegade renew reopened reopening reorders repackagers repacked replay replicating
reprocessing reproducer republic requestor requirers rerunning rescaled reschedules rescue
researcher reshapes resid resides residing restarted restarting restarts restoration restricting
restroom resurrecting retag retire retired retract retrain retransmitted retro reunites
reusability revalidate reveals reverb reverted reviews revise revisit revisited reviver
revocable revocations revolving revs rewriting rhinoceros rhubarb ribbon richly rickshaw ride
ridiculous ridiculously righty ringed ripple risking river roasted rob rocky rod roller rollover
roof rooster rosette rosy router rowboat rowing royal royalties rub rubbish rubric rubrics
rudimentary ruff rugby ruled ruler rumble runaway sacrificed sad saddle safari sail sailboat
salad salute salvage samp sand sandal sandwich sandy sanitise sanitised sari sash sass satara
satchel satellite satisfactory saturated saucer sauropod savannah savoring sawtooth saxophone
saying scad scaffolding scanners scape scar scarf scavenge scenes scheduler schemata science
scientist scissors scooter scorecard scorpion scraped scrapes scraping scream screaming screens
scrolls seal sealed seamlessly searchable searcher seashell seat secondly sectioning secures
seeding seedless seedling seeking seemingly segmented seldom selectable selections selectively
semaphore sematic semiconductor senders sentry sequenced sequencer sequencing sequoia
serendipity seta settles setups shade shamrock shapeless shapely shaper shaved shaving sheaf
shebangs sheep sheets shenanigans shield shiny ship shippable shipped shipping shirt shit shoes
shooting shortcake shortens shorts shove shower shri shrine shrugging shrunk shuffling shushing
shuts shuttlecock sidebar sided sidestep sienna sierra sieves signatory signers signifying
silhouette similarities simplification simplistic simulated singer singly singularity sinus
sister sits sitting skate skateboard skeleton sketches skier skis skull skunk sky skylark slab
sled sleepy sleuth slider slides slim slip slippery slips slop sloppily sloth slowly slows
smarty smell smiling smirk smirking smithy smoking smoothly smuggle snail snake snapshotted
sneezing snowball snowboarder snowflake snowman sob soccer society softball solarized sold
solidity somebody sons sooner sorry sos sot sought sourcing southern spade spaghetti spare
sparkle sparkler sparkles speaker speakers specifiable spectra specular sped speedboat speeding
speer spherical spheroidal spice spider spies spike spikes spilt spitfire spits splayed
splitters spoiled spoked spoken sponge sponsor sponsored sponsoring sponsors spoofing spoon
sports spotted spouting springer springs sprinkled spy squeak squinting squish squoosh sri
stablish stadium stages stalled stalling standardise standby standout stashed stashes station
stationery statue statutory staying steam steaming steamy steel stemming stems stepped stepping
stereo stethoscope stew sticks stitch stopwatch strangely stranger straw strawberry strictest
strikes stringy stripper stroked strokes struck stubbed study stuffed stun stupid stylus
subblocks subdivide subdivision subfield subframe subgraph sublime subnets suboptimal subplot
subplots subproblems subsampled subspaces subsume subsystem subtasks subtest subtests subtitles
subtleties subtly succession sue suffer suffered suffices suffixing suggester suitably
summarised summarizing summer sunder sunflower sunglasses sunny sunrise sunset superclasses
supercollider superficial superhero superlative superposes supers superseded suppose
suppressions surd surfing surpassed surplus surrounds survived sushi suspending suspicion
swallowed swan sweat sweet swig swimmer swimming swimsuit swirl swords symmetrical symmetries
synagogue synched synthesis synthesizer syringe systematic taco tact tads tailed takeout
takeover taller tampering tangential tangerine tango taper tapering taxi teacher teacup tear
tears technological technologies technologist teddy telescope television temperature temple
tennis tentatively terminators terminology terminus terraform terrier testers thankfully theater
theorem thereby therein thermometer thick thickness thirty thrashing thrift throttled thumbs
thunder tic tiddler tiddly tie tildes tilt timelines timescale tipped tipping tire tired tissue
titi toggles toggling tom tonga tongue tons toolbox tooth topologically tornado tortious totals
tower town traceable trackball tractor trad tradeoff train trained tram tramway transact
transceivers transcript transducer transferee transferring transitively transmitting transported
transports transposition trap trapped trapping trash travel traveling traverses tray treaty
treetop trend tret triad triage trials tricked trickier trickle trickled trident trigged triumph
trolleybus trophy tropical troubles troublesome trow truck trumpet trusting truthful
truthfulness tsadi tube tulip tumbler tunnels tups turban turbulence turkey turks turnstile
tutorials tuxedo twa twig twine twofold typecast typeset ubiquity udo ultimate ulu umbrella
unacceptable unacknowledged unadjusted unamused unblocked unblocks unbuilt uncapped
uncertainties unchanging unclosing unclutter unconnected unconsumed unconverted uncork
undecidable undecorated underage underestimates underneath underruns understandably
understanding understandings undertake undertaken underway unenforceable unequivocally
unexplored unforeseen unfree unicorn unify unimportant unintentionally uninteresting uniqueness
uniques unknowable unloading unloads unlocking unmapped unmasking unmasks unmet unobserved
unpaired unpressed unraveled unraveling unreadable unrecorded unrewarding unseen unshared
unshifted unshifting unsliced unsplit unspoken unstacked unstring unsuited untypical unwind
upcoming updater upgrades upright upwards usefully utilizing utterance utterances vacancy vague
validly valuable valueless vampire varia variability varieties varnish vast vav vaw vee vehicle
veil vendors verifications vert vest victim victor victory videocassette violate violin virgin
virtue visualizations visualizing visually vital voice voices volcano volleyball voltage
vomiting voted vulgar waffle waiver waives wales wally waning warcraft ward warm warmup warner
warrant warranted warriors wast wastebasket wastes watermark watermelon waveform waving wavy waw
wax waxing weakly wearing weary weather wedding weekends weekly weirdness weirdnesses wether
whale whatsoever wheelchair wherein whine whiny wholly wich widgets widows wilco wildly
willfully willing wilted windowed windowing wine wings winking wisdom woefully wolf woman womans
women wonder woozy workloads workstation worried worship wreaks wren wrench wrestling wrongness
wry xu yank yap yar yawning yeah yin young younger youngest yum zany zeroing zipper zipping zips
zombies zones
cohort experiment inventory refund rollout supplier tax warehouse
`;

function loadHumpWords(): Set<string> {
  const words = new Set<string>();
  const text = HUMP_WORD_TEXT;
  let start = 0;
  for (let i = 0; i <= text.length; i += 1) {
    const code = i === text.length ? 32 : text.charCodeAt(i);
    if (code === 32 || code === 10 || code === 13 || code === 9) {
      if (i > start) words.add(text.slice(start, i));
      start = i + 1;
    }
  }
  return words;
}

const HUMP_WORDS: ReadonlySet<string> = loadHumpWords();

/**
 * Light stem of [word], the QA s/es/ies/ed/ing/er/ers/ly/ion rules.
 * A candidate counts only when it is at least 3 letters. The word
 * itself is not a stem. One check per matching suffix.
 */
function stemHits(word: string): boolean {
  const hit = (stem: string): boolean => stem.length >= 3 && HUMP_WORDS.has(stem);
  if (word.endsWith('ies') && hit(word.slice(0, -3) + 'y')) return true;
  if (word.endsWith('es') && hit(word.slice(0, -2))) return true;
  if (word.endsWith('s') && hit(word.slice(0, -1))) return true;
  if (word.endsWith('ed')) {
    if (hit(word.slice(0, -2)) || hit(word.slice(0, -1))) return true;
  }
  if (word.endsWith('ing')) {
    if (hit(word.slice(0, -3)) || hit(word.slice(0, -3) + 'e')) return true;
  }
  if (word.endsWith('er')) {
    if (hit(word.slice(0, -2)) || hit(word.slice(0, -1))) return true;
  }
  if (word.endsWith('ers') && hit(word.slice(0, -3))) return true;
  if (word.endsWith('ly') && hit(word.slice(0, -2))) return true;
  if (word.endsWith('ion')) {
    if (hit(word.slice(0, -3)) || hit(word.slice(0, -3) + 'e')) return true;
  }
  return false;
}

/**
 * True when [from, to) is a dictionary word, ignoring a leading capital.
 * A light stem of an entry counts. One pass. The span is at most 16 letters.
 */
export function humpWordAt(line: string, from: number, to: number): boolean {
  const n = to - from;
  if (n < 2 || n > 16) return false;
  let lower = '';
  for (let i = from; i < to; i += 1) {
    const code = line.charCodeAt(i);
    if (code >= 97 && code <= 122) lower += String.fromCharCode(code);
    else if (code >= 65 && code <= 90) lower += String.fromCharCode(code + 32);
    else return false;
  }
  if (HUMP_WORDS.has(lower)) return true;
  return stemHits(lower);
}
