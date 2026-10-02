use rustler::{Encoder, Env, ListIterator, Term};
use zxcvbn::Entropy;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        nil,
        score,
        guesses,
        guesses_log10,
        calc_time,
        crack_times_display,
        online_throttling_100_per_hour,
        online_no_throttling_10_per_second,
        offline_slow_hashing_1e4_per_second,
        offline_fast_hashing_1e10_per_second,
        feedback,
        warning,
        suggestions,
    }
}

rustler::init!("Elixir.Zxcvbn");

struct EntropyWrap {
    entropy: Entropy,
}

impl Encoder for EntropyWrap {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let entropy = &self.entropy;

        let crack_times = ::rustler::types::map::map_new(env)
            .map_put(
                atoms::offline_fast_hashing_1e10_per_second().encode(env),
                entropy
                    .crack_times()
                    .offline_fast_hashing_1e10_per_second()
                    .to_string()
                    .encode(env),
            )
            .ok()
            .unwrap()
            .map_put(
                atoms::offline_slow_hashing_1e4_per_second().encode(env),
                entropy
                    .crack_times()
                    .offline_slow_hashing_1e4_per_second()
                    .to_string()
                    .encode(env),
            )
            .ok()
            .unwrap()
            .map_put(
                atoms::online_throttling_100_per_hour().encode(env),
                entropy
                    .crack_times()
                    .online_throttling_100_per_hour()
                    .to_string()
                    .encode(env),
            )
            .ok()
            .unwrap()
            .map_put(
                atoms::online_no_throttling_10_per_second().encode(env),
                entropy
                    .crack_times()
                    .online_no_throttling_10_per_second()
                    .to_string()
                    .encode(env),
            )
            .ok()
            .unwrap();

        let mut feedback = ::rustler::types::map::map_new(env);
        feedback = match entropy.feedback() {
            Some(feedback_value) => feedback
                .map_put(
                    atoms::warning().encode(env),
                    match feedback_value.warning() {
                        Some(warning_value) => warning_value.to_string().encode(env),
                        None => atoms::nil().encode(env),
                    },
                )
                .ok()
                .unwrap()
                .map_put(
                    atoms::suggestions().encode(env),
                    match feedback_value.suggestions() {
                        [] => atoms::nil().encode(env),
                        vector => vector
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .encode(env),
                    },
                )
                .ok()
                .unwrap(),
            None => feedback
                .map_put(atoms::warning().encode(env), atoms::nil().encode(env))
                .ok()
                .unwrap()
                .map_put(atoms::suggestions().encode(env), atoms::nil().encode(env))
                .ok()
                .unwrap(),
        };

        let result = ::rustler::types::map::map_new(env)
            .map_put(
                atoms::score().encode(env),
                u8::from(entropy.score()).encode(env),
            )
            .ok()
            .unwrap()
            .map_put(atoms::guesses().encode(env), entropy.guesses().encode(env))
            .ok()
            .unwrap()
            .map_put(
                atoms::guesses_log10().encode(env),
                entropy.guesses_log10().encode(env),
            )
            .ok()
            .unwrap()
            .map_put(atoms::crack_times_display().encode(env), crack_times)
            .ok()
            .unwrap()
            .map_put(
                atoms::calc_time().encode(env),
                // `calculation_time()` is a `Duration`
                // in seconds. We're expecting ms so
                // we multiply that by 1000.
                entropy
                    .calculation_time()
                    .mul_f32(1000.0)
                    .as_secs_f32()
                    .encode(env),
            )
            .ok()
            .unwrap()
            .map_put(atoms::feedback().encode(env), feedback)
            .ok()
            .unwrap();

        result
    }
}

enum RunReturn {
    Ok(Entropy),
    Error(&'static str),
}

impl Encoder for RunReturn {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            RunReturn::Ok(entropy) => (
                atoms::ok(),
                EntropyWrap {
                    entropy: entropy.to_owned(),
                },
            )
                .encode(env),
            RunReturn::Error(reason) => (atoms::error(), reason).encode(env),
        }
    }
}

#[rustler::nif(schedule = "DirtyCpu", name = "run_nif")]
fn run(password: &str, inputs: ListIterator) -> RunReturn {
    // zxcvbn 3 scores a blank password as 0; keep the error that `Zxcvbn.run` documents.
    if password.is_empty() {
        return RunReturn::Error("blank_password");
    }

    let user_inputs = inputs.map(|i| i.decode().unwrap_or("")).collect::<Vec<_>>();

    RunReturn::Ok(zxcvbn::zxcvbn(password, &user_inputs))
}
