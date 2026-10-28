/**
 * Dictionary for a camelCase hump after a truncated key.
 * A hump counts when it is one of these words. Shape alone does not:
 * a random vowel-consonant run stays key material.
 *
 * This list is self-authored. It is the identifier humps this package
 * already keeps (the hand lists in the redact tests, the identifier-word
 * set, and the code tokens below) plus common code words. It is not a
 * copy or a subset of a third-party word list.
 *
 * v1.0.61 packed two outside lists into this file: the hermitdave
 * FrequencyWords 2018 English 50,000 (repository code under MIT, word
 * content under CC-BY-SA-4.0) and first20hours/google-10000-english
 * (derived from the Google Web Trillion Word Corpus via Peter Norvig;
 * that list is not cleared for commercial redistribution). Share-alike
 * and the Linguistic Data Consortium terms do not allow shipping those
 * lists under this package's MIT license, so they are not shipped.
 * Do not filter those lists back in.
 *
 * Identifier abbreviations also stay in identifierWordAt.
 */
const HUMP_WORD_TEXT = `
ab access account action active adapter add address aes align allocate allow
allowed amount ansible api app append application apply args arguments argv asset
async asynchronous atob audio audit auth autoscaler backend background backoff backup badge
balance bar base batchnorm battery bcrypt bigquery bin block body book bootstrap
border box branch breaker broker btn btoa bucket buffer build bulkhead bundle
button by bytecode cache calculate calculation callback camel canonicalize canonicalized canonicalizer canvas
capture case catalog certificate cfg change changes check checkout checksum child cipher
ciphertext circuit claim class clear cli click clickhouse client close code cohort
collect color column command comment commit compile components compose compute concat config
configmap configuration configure connection const consumer containerd content context contract control controller
convert cookie correct count counter coverage create cronjob crypto csrf ctx cuda
currency customer cycle dashboard data database dataloader db debounce decode decompress dedupe
dehydrate delete dependency deployment deque descriptor deselect deserialize deserializer details dev digest
dir dirname discount display docker dockerfile docs document dotnet downstream downward dst
dtype ecdsa elasticsearch element email embedding encode encoded encrypt endpoint enqueue entry
enum enumerable env environment error esbuild eslint event executable experiment expired export
exporter extname extra fastapi fastlane feature fetch field file files filesystem filter
fingerprint firebase firestore flag flow fn focus font form format frame frontend
function gateway gauge generate get gradle grafana grant graph graphql group grpc
handle handler header height helmfile histogram history hmac home horizontal horse host
hostname html http hump id idempotent identifier identity idx image impl import
incoming index indexed ingress init initializer input install invalidate inventory invoice is
isolation item iterable iterator jar javascript jitter job journal js json jsonify
jwt kafka key keydown keystore keyup kubeconfig kubectl kubelet kubernetes kustomize label
latency ledger len lexer lib lifecycle limiter line linq list listener load
loader localhost lock log logger logout long main manager manifest map margin
marshaller match maven md measure memoize merge message method metric middleware minikube
module monthly msg multipart mutex name namespace nav network nginx node normalize
notes notification now nuget nullable num numpy nunit oauth object oidc opcode
open opensearch openssl operand optimizer order package packet padding page paragraph params
parent parse parser passphrase password path pathname paths pattern payload payment performance
permission persistent personal pkg plain plaintext pod policy port postgres postgresql preferences
prefetch prepend prettify price prisma process producer product profile project prometheus protobuf
publish pydantic quantile query random rate ratio read readme readonly receipt record
records redis redshift reducer ref refactor refresh refs refund regex register reindex
rel release render repo report repository req request res reset resize resolve
resolver response result results retry review revoke role rollout rollup rotate route
row rs rsa run runtimeclass sanitize save schedule scrape screenshot search section
security selector send sequelize serialize serializer serilog server service session set settings
sha share sheet shipping shutdown signature signin signing sinon site size sklearn
socket softmax sort span specifier split sqlalchemy src staple start state statement
status stdin stdout stop storage store str stream strength stringify style stylelint
stylesheet submit substring summary supabase supplier swift synchronization table tag task tax
telemetry template tensor terraform test text this thread throughput timestamp title tmp
toggle token tokenizer total trace trie truncate trusted ts tsx typeorm typescript
uncommitted unescape unicode unmarshaller unmount unmute update upsert upstream url user util
uuid validate validator value variant verify version very video view vitest volume
vue warehouse web webhook webpack websocket whitespace widget width wildcard window words
worker workload write xunit yaml
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
 * True when [from, to) is a dictionary word, ignoring a leading capital.
 * One pass. The span is at most 16 letters.
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
  return HUMP_WORDS.has(lower);
}
