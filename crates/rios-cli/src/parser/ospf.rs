//! One grammar for OSPF external-origination parsing and contextual help.
use super::*;
use rios_config::{OspfDefaultRoute, OspfRedistribute};
pub(super) struct Options {
    pub command: Option<Command>,
    pub choices: Vec<&'static str>,
}
pub(super) fn options(action: Action, args: &[Token<'_>]) -> Result<Options, ParseError> {
    let default = matches!(action, Action::OspfDefault);
    let flag = if default { "always" } else { "subnets" };
    let mut seen = std::collections::BTreeSet::new();
    let mut metric = if default { 1 } else { 20 };
    let mut type_two = true;
    let mut always = false;
    let keywords = [flag, "metric", "metric-type"];
    let mut index = 0;
    while index < args.len() {
        let word = unique_choice(&args[index], &keywords)?;
        if !seen.insert(word) {
            return Err(invalid(args[index].offset, "duplicate OSPF option"));
        }
        index += 1;
        if word == flag {
            always = default;
            continue;
        }
        let choices = if word == "metric" {
            vec!["<0-16777214>"]
        } else {
            vec!["1", "2"]
        };
        let Some(value) = args.get(index) else {
            return Ok(Options {
                command: None,
                choices,
            });
        };
        if word == "metric" {
            metric = value
                .text
                .parse::<u32>()
                .ok()
                .filter(|v| *v < 0x00ff_ffff)
                .ok_or_else(|| invalid(value.offset, "metric must be 0-16777214"))?;
        } else {
            type_two = match value.text {
                "1" => false,
                "2" => true,
                _ => return Err(invalid(value.offset, "metric type must be 1 or 2")),
            };
        }
        index += 1;
    }
    let command = if default {
        Command::SetOspfDefault(Some(OspfDefaultRoute {
            always,
            metric,
            type_two,
        }))
    } else {
        Command::SetOspfRedistributeStatic(Some(OspfRedistribute { metric, type_two }))
    };
    let mut choices = vec!["<cr>"];
    choices.extend(
        [flag, "metric", "metric-type"]
            .into_iter()
            .filter(|word| !seen.contains(word)),
    );
    Ok(Options {
        command: Some(command),
        choices,
    })
}
pub(super) fn suggest(
    action: Action,
    args: &[Token<'_>],
    partial: &str,
    start: usize,
) -> Result<Vec<Suggestion>, ParseError> {
    Ok(options(action, args)?
        .choices
        .into_iter()
        .filter(|word| word.starts_with('<') || word.starts_with(&partial.to_ascii_lowercase()))
        .map(|word| Suggestion {
            word: word.into(),
            help: String::new(),
            start,
        })
        .collect())
}
