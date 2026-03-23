use super::{BoxError, CorrelationStore, Label, Point, Row};
use redis::{Client, cmd};
use std::env;
use std::hash::{Hash, Hasher};
use std::time::Duration;

/// A [`CorrelationStore`] backend backed by Redis TimeSeries.
///
/// Each time-series is stored under the key `sigmars:ts:{metric}:{label_fp}`,
/// where `label_fp` is a hex hash of the sorted label set (or `_` when there
/// are no labels).  An internal `__metric__` label is attached to every key so
/// that [`select_all`] can retrieve all series for a given metric via
/// `TS.MRANGE … FILTER __metric__={metric}`.
///
/// # Connection URL
///
/// The connection URL is read from the `REDIS_URL` environment variable and
/// falls back to `redis://127.0.0.1/` when the variable is not set.
///
/// # Requirements
///
/// Redis must have the [RedisTimeSeries] module loaded.
///
/// [RedisTimeSeries]: https://redis.io/docs/stack/timeseries/
pub struct RedisStore {
    client: Client,
    retention_ms: u64,
}

impl RedisStore {
    fn redis_url() -> String {
        env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string())
    }

    /// Derive a stable Redis key for a (metric, label-set) pair.
    fn ts_key(metric: &str, labels: &[Label]) -> String {
        if labels.is_empty() {
            format!("sigmars:ts:{}:_", metric)
        } else {
            let mut sorted: Vec<(&str, &str)> =
                labels.iter().map(|l| (l.name.as_str(), l.value.as_str())).collect();
            sorted.sort_by_key(|(k, _)| *k);
            let fp: String = sorted
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\x1f");
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            fp.hash(&mut hasher);
            format!("sigmars:ts:{}:{:016x}", metric, hasher.finish())
        }
    }

    /// Parse the array-of-pairs reply from `TS.RANGE`.
    fn parse_ts_range(v: redis::Value) -> Result<Vec<Point>, BoxError> {
        match v {
            redis::Value::Nil => Ok(Vec::new()),
            redis::Value::Array(items) => {
                let mut points = Vec::with_capacity(items.len());
                for item in items {
                    let pair = match item {
                        redis::Value::Array(p) => p,
                        _ => return Err("unexpected point format in TS.RANGE response".into()),
                    };
                    if pair.len() != 2 {
                        return Err("TS.RANGE point array must have exactly 2 elements".into());
                    }
                    let ts = redis_value_to_i64(&pair[0])?;
                    let val = redis_value_to_f64(&pair[1])?;
                    points.push(Point::new(ts, val));
                }
                Ok(points)
            }
            _ => Err("unexpected TS.RANGE response type".into()),
        }
    }

    /// Parse the nested reply from `TS.MRANGE … WITHLABELS`.
    ///
    /// Each entry is `[key_name, [[label_name, label_value], …], [[ts, val], …]]`.
    fn parse_ts_mrange(v: redis::Value) -> Result<Vec<(Vec<Label>, Vec<Point>)>, BoxError> {
        match v {
            redis::Value::Nil => Ok(Vec::new()),
            redis::Value::Array(series) => {
                let mut result = Vec::with_capacity(series.len());
                for s in series {
                    let fields = match s {
                        redis::Value::Array(f) => f,
                        _ => return Err("unexpected series entry in TS.MRANGE response".into()),
                    };
                    if fields.len() < 3 {
                        return Err("TS.MRANGE series entry must have at least 3 fields".into());
                    }
                    // fields[0] = key name  (ignored)
                    // fields[1] = labels    [[name, value], ...]
                    // fields[2] = points    [[ts, val], ...]
                    let labels = parse_labels_value(&fields[1])?;
                    let points = Self::parse_ts_range(fields[2].clone())?;
                    result.push((labels, points));
                }
                Ok(result)
            }
            _ => Err("unexpected TS.MRANGE response type".into()),
        }
    }
}

/// Extract user-visible labels from a Redis TimeSeries label array, stripping
/// the internal `__metric__` label.
fn parse_labels_value(v: &redis::Value) -> Result<Vec<Label>, BoxError> {
    let items = match v {
        redis::Value::Array(a) => a,
        _ => return Ok(Vec::new()),
    };
    let mut labels = Vec::new();
    for item in items {
        let pair = match item {
            redis::Value::Array(p) => p,
            _ => return Err("unexpected label entry format in TS.MRANGE".into()),
        };
        if pair.len() != 2 {
            return Err("label pair must have exactly 2 elements".into());
        }
        let name = redis_value_to_string(&pair[0])?;
        let value = redis_value_to_string(&pair[1])?;
        if name != "__metric__" {
            labels.push(Label::new(name, value));
        }
    }
    Ok(labels)
}

fn redis_value_to_i64(v: &redis::Value) -> Result<i64, BoxError> {
    match v {
        redis::Value::Int(i) => Ok(*i),
        redis::Value::BulkString(b) => String::from_utf8_lossy(b)
            .parse::<i64>()
            .map_err(|e| Box::new(e) as BoxError),
        redis::Value::SimpleString(s) => {
            s.parse::<i64>().map_err(|e| Box::new(e) as BoxError)
        }
        _ => Err("cannot convert Redis value to i64".into()),
    }
}

fn redis_value_to_f64(v: &redis::Value) -> Result<f64, BoxError> {
    match v {
        redis::Value::Double(d) => Ok(*d),
        redis::Value::Int(i) => Ok(*i as f64),
        redis::Value::BulkString(b) => String::from_utf8_lossy(b)
            .parse::<f64>()
            .map_err(|e| Box::new(e) as BoxError),
        redis::Value::SimpleString(s) => {
            s.parse::<f64>().map_err(|e| Box::new(e) as BoxError)
        }
        _ => Err("cannot convert Redis value to f64".into()),
    }
}

fn redis_value_to_string(v: &redis::Value) -> Result<String, BoxError> {
    match v {
        redis::Value::BulkString(b) => Ok(String::from_utf8_lossy(b).into_owned()),
        redis::Value::SimpleString(s) => Ok(s.clone()),
        redis::Value::Int(i) => Ok(i.to_string()),
        _ => Err("cannot convert Redis value to String".into()),
    }
}

fn is_key_not_found(e: &redis::RedisError) -> bool {
    e.kind() == redis::ErrorKind::ResponseError
        && e.to_string().contains("key does not exist")
}

impl CorrelationStore for RedisStore {
    fn new() -> Result<Self, BoxError> {
        let client = Client::open(Self::redis_url()).map_err(|e| Box::new(e) as BoxError)?;
        Ok(Self { client, retention_ms: 0 })
    }

    fn new_with_expiry(expire: Duration) -> Result<Self, BoxError> {
        let client = Client::open(Self::redis_url()).map_err(|e| Box::new(e) as BoxError)?;
        Ok(Self {
            client,
            retention_ms: expire.as_millis() as u64,
        })
    }

    /// Write rows into Redis TimeSeries.
    ///
    /// Uses `TS.ADD … RETENTION … LABELS …` which auto-creates the key on the
    /// first insertion.  The `__metric__` label is always written so that
    /// `select_all` can filter by metric name.  `ON_DUPLICATE LAST` is set to
    /// tolerate any duplicate timestamps inserted within the same millisecond.
    fn insert_rows(&self, rows: &[Row]) -> Result<(), BoxError> {
        let mut conn = self.client.get_connection().map_err(|e| Box::new(e) as BoxError)?;

        for row in rows {
            let key = Self::ts_key(&row.metric, &row.labels);

            let mut c = cmd("TS.ADD");
            c.arg(&key).arg(row.point.timestamp).arg(row.point.value);

            if self.retention_ms > 0 {
                c.arg("RETENTION").arg(self.retention_ms);
            }

            c.arg("ON_DUPLICATE").arg("LAST");

            // __metric__ label comes first so MRANGE FILTER works, then user labels.
            c.arg("LABELS").arg("__metric__").arg(&row.metric);
            for l in &row.labels {
                c.arg(&l.name).arg(&l.value);
            }

            c.query::<redis::Value>(&mut conn).map_err(|e| Box::new(e) as BoxError)?;
        }
        Ok(())
    }

    /// Query a single time-series by metric name and exact label set.
    fn select(
        &self,
        metric: &str,
        labels: &[Label],
        start: i64,
        end: i64,
    ) -> Result<Vec<Point>, BoxError> {
        let mut conn = self.client.get_connection().map_err(|e| Box::new(e) as BoxError)?;
        let key = Self::ts_key(metric, labels);

        match cmd("TS.RANGE").arg(&key).arg(start).arg(end).query::<redis::Value>(&mut conn) {
            Ok(v) => Self::parse_ts_range(v),
            Err(e) if is_key_not_found(&e) => Ok(Vec::new()),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Query all time-series for a metric, returning each label set with its points.
    ///
    /// Uses `TS.MRANGE … WITHLABELS FILTER __metric__={metric}` to enumerate
    /// every label-set variant stored under this metric.
    fn select_all(
        &self,
        metric: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<(Vec<Label>, Vec<Point>)>, BoxError> {
        let mut conn = self.client.get_connection().map_err(|e| Box::new(e) as BoxError)?;
        let filter = format!("__metric__={}", metric);

        let result = cmd("TS.MRANGE")
            .arg(start)
            .arg(end)
            .arg("WITHLABELS")
            .arg("FILTER")
            .arg(&filter)
            .query::<redis::Value>(&mut conn)
            .map_err(|e| Box::new(e) as BoxError)?;

        Self::parse_ts_mrange(result)
    }
}
