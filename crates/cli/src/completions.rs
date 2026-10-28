//! Shell completion scripts: `clap_complete` writes the subcommands, options
//! and paths from the command definition; the arguments that name a profile
//! (`value_name = "PROFILE"`) are completed by asking `omnitunctl profiles
//! --names`, with the `--config` of the command line. `clap_complete`'s own
//! dynamic completion is behind an unstable feature.

use anyhow::bail;
use clap::ValueEnum;

/// The value that marks an argument taking a profile.
pub const PROFILE: &str = "PROFILE";

#[derive(Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
}

/// The completion script for `shell`.
pub fn script(shell: Shell, command: &mut clap::Command) -> anyhow::Result<String> {
    let name = command.get_name().to_owned();
    let mut out = Vec::new();
    let generator = match shell {
        Shell::Bash => clap_complete::Shell::Bash,
        Shell::Zsh => clap_complete::Shell::Zsh,
    };
    clap_complete::generate(generator, command, &name, &mut out);
    let generated = String::from_utf8(out)?;
    let profiles = profile_arguments(command);
    if profiles.is_empty() {
        bail!("no argument is marked value_name = \"{PROFILE}\"");
    }
    match shell {
        Shell::Bash => bash(&generated, &name, &profiles, &value_options(command)),
        Shell::Zsh => zsh(&generated, &name, &profiles),
    }
}

/// An argument that takes a profile: the path of its subcommand, from the
/// top (`["secret", "set"]`), and its id.
#[derive(Debug, PartialEq, Eq)]
struct ProfileArgument {
    path: Vec<String>,
    id: String,
}

fn profile_arguments(command: &clap::Command) -> Vec<ProfileArgument> {
    fn walk(command: &clap::Command, path: &mut Vec<String>, found: &mut Vec<ProfileArgument>) {
        for arg in command.get_positionals() {
            if arg.get_value_names().is_some_and(|names| names.iter().any(|n| n == PROFILE)) {
                found.push(ProfileArgument { path: path.clone(), id: arg.get_id().to_string() });
            }
        }
        for sub in command.get_subcommands() {
            path.push(sub.get_name().to_owned());
            walk(sub, path, found);
            path.pop();
        }
    }
    let mut found = Vec::new();
    walk(command, &mut Vec::new(), &mut found);
    found
}

/// Options taking a value anywhere in the tree: the word after them is
/// that value, never a profile.
fn value_options(command: &clap::Command) -> Vec<String> {
    fn walk(command: &clap::Command, found: &mut Vec<String>) {
        for arg in command.get_arguments().filter(|a| !a.is_positional() && a.get_action().takes_values()) {
            found.extend(arg.get_long().map(|l| format!("--{l}")));
            found.extend(arg.get_short().map(|s| format!("-{s}")));
        }
        for sub in command.get_subcommands() {
            walk(sub, found);
        }
    }
    let mut found = Vec::new();
    walk(command, &mut found);
    found.sort();
    found.dedup();
    found
}

/// Replaces `pattern`, which must be there.
fn replace(text: &str, pattern: &str, with: &str) -> anyhow::Result<String> {
    if !text.contains(pattern) {
        bail!("the generated script changed: {pattern:?} not found");
    }
    Ok(text.replace(pattern, with))
}

/// A zsh `_arguments` spec of a positional among `ids`, completed by
/// default, with `function` as its action: `'*::names -- Help:_default'`.
fn retarget(line: &str, ids: &[&str], function: &str) -> Option<String> {
    let spec = line.trim_start().strip_prefix('\'')?;
    let spec = spec.strip_prefix('*').unwrap_or(spec);
    let rest = spec.strip_prefix("::").or_else(|| spec.strip_prefix(':'))?;
    let id = ids
        .iter()
        .find(|id| rest.strip_prefix(**id).is_some_and(|after| after.starts_with(':') || after.starts_with(" -- ")))?;
    let (head, tail) = line.split_once(":_default'")?;
    // The action is the spec's last field: nothing but the help may sit
    // between the id and it.
    let message = &head[head.find(*id)? + id.len()..];
    if message.contains(':') {
        return None;
    }
    Some(format!("{head}:{function}'{tail}"))
}

/// zsh: the profile arguments' action becomes `_<name>_profiles`, defined
/// before the generated function. The command line is read from `$BUFFER`:
/// `_arguments` narrows `words` to the subcommand's own.
fn zsh(generated: &str, name: &str, profiles: &[ProfileArgument]) -> anyhow::Result<String> {
    let function = format!("_{name}_profiles");
    let ids: Vec<&str> = profiles.iter().map(|p| p.id.as_str()).collect();
    let mut replaced = 0;
    let mut script = String::with_capacity(generated.len());
    for line in generated.split_inclusive('\n') {
        match retarget(line, &ids, &function) {
            Some(new) => {
                replaced += 1;
                script.push_str(&new);
            }
            None => script.push_str(line),
        }
    }
    // One line per argument: fewer means the generator's format changed,
    // more that a profile argument's id names another argument too.
    if replaced != profiles.len() {
        bail!("{replaced} zsh argument lines for {} profile arguments: the generated script changed", profiles.len());
    }
    let helper = format!(
        r#"
# Profile names, from the profiles file the command line names (--config).
{function}() {{
    local -a line config names
    local i start command file
    line=(${{(z)BUFFER}})
    # The command is the word naming this program: sudo, env or VAR=value
    # may come before it.
    for (( start = 1; start <= $#line; start++ )); do
        [[ ${{${{(Q)line[start]}}:t}} == {name} ]] && break
    done
    (( start > $#line )) && return 1
    command=${{(Q)line[start]}}
    for (( i = start + 1; i <= $#line; i++ )); do
        case $line[i] in
            --config) file=${{(Q)line[i+1]}} ;;
            --config=*) file=${{(Q)${{line[i]#--config=}}}} ;;
        esac
    done
    [[ $file == '~/'* ]] && file=$HOME/${{file#\~/}}
    [[ -n $file ]] && config=(--config "$file")
    names=("${{(@f)$("$command" $config profiles --names 2>/dev/null)}}")
    compadd -- "${{names[@]}}"
}}
"#
    );
    let header = format!("#compdef {name}\n");
    let Some(body) = script.strip_prefix(&header) else {
        bail!("the generated script changed: no {header:?} first line");
    };
    Ok(format!("{header}{helper}{body}"))
}

/// bash: before the generated dispatch on the subcommand, a profile
/// argument's position is answered with the profile names, escaped for the
/// shell.
fn bash(generated: &str, name: &str, profiles: &[ProfileArgument], options: &[String]) -> anyhow::Result<String> {
    let function = format!("_{name}_profiles");
    let mut commands: Vec<String> = profiles
        .iter()
        .map(|p| std::iter::once(name.to_owned()).chain(p.path.iter().cloned()).collect::<Vec<_>>().join("__subcmd__"))
        .collect();
    commands.sort();
    commands.dedup();
    let options = options.join("|");
    let hook = format!(
        "    if [[ ${{cur}} != -* ]]; then\n\
         \x20       case \"${{cmd}}\" in\n\
         \x20           {}) {function} \"${{cur}}\" \"${{prev}}\" && return 0 ;;\n\
         \x20       esac\n\
         \x20   fi\n\
         \x20   case \"${{cmd}}\" in\n",
        commands.join("|")
    );
    let script = replace(generated, "    case \"${cmd}\" in\n", &hook)?;
    let helper = format!(
        r#"# Profile names, from the profiles file the command line names
# (--config); fails after an option that takes a value.
{function}() {{
    local cur="$1" prev="$2" i name file=
    local -a config
    case "$prev" in
        {options}) return 1 ;;
    esac
    for (( i = 1; i < COMP_CWORD; i++ )); do
        case "${{COMP_WORDS[i]}}" in
            # = is in COMP_WORDBREAKS: --config=a comes as --config, =, a.
            --config) if [[ "${{COMP_WORDS[i+1]}}" == = ]]; then
                    file="${{COMP_WORDS[i+2]}}"
                else
                    file="${{COMP_WORDS[i+1]}}"
                fi ;;
            --config=*) file="${{COMP_WORDS[i]#--config=}}" ;;
        esac
    done
    # The word as typed: unescaped, and ~ expanded.
    file="${{file//\\/}}"
    [[ "$file" == "~/"* ]] && file="$HOME/${{file#\~/}}"
    [[ -n "$file" ]] && config=(--config "$file")
    COMPREPLY=()
    while IFS= read -r name; do
        if [[ "$name" == "${{cur//\\/}}"* ]]; then
            COMPREPLY+=("$(printf '%q' "$name")")
        fi
    done < <("${{COMP_WORDS[0]}}" "${{config[@]}}" profiles --names 2>/dev/null)
    return 0
}}

"#
    );
    Ok(format!("{helper}{script}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, Command};

    fn command() -> Command {
        Command::new("tool")
            .arg(Arg::new("config").long("config").global(true))
            .subcommand(Command::new("connect").arg(Arg::new("names").value_name(PROFILE).num_args(0..)))
            .subcommand(
                Command::new("log").arg(Arg::new("names").value_name(PROFILE).num_args(0..).help("Profile names.")),
            )
            .subcommand(Command::new("import").arg(Arg::new("path")))
            .subcommand(
                Command::new("secret").subcommand(
                    Command::new("set")
                        .arg(Arg::new("profile").value_name(PROFILE))
                        .arg(Arg::new("key").long("key").short('k')),
                ),
            )
    }

    #[test]
    fn profile_arguments_are_found_by_their_value_name() {
        assert_eq!(
            profile_arguments(&command()),
            [
                ProfileArgument { path: vec!["connect".into()], id: "names".into() },
                ProfileArgument { path: vec!["log".into()], id: "names".into() },
                ProfileArgument { path: vec!["secret".into(), "set".into()], id: "profile".into() },
            ]
        );
    }

    #[test]
    fn options_taking_a_value_are_listed() {
        assert_eq!(value_options(&command()), ["--config", "--key", "-k"]);
    }

    #[test]
    fn zsh_profile_arguments_use_the_profile_function() {
        let script = script(Shell::Zsh, &mut command()).unwrap();
        assert!(script.starts_with("#compdef tool\n"), "{script}");
        assert!(script.contains("_tool_profiles() {"), "{script}");
        assert!(script.contains(":names:_tool_profiles'") && script.contains(":profile:_tool_profiles'"), "{script}");
        assert!(!script.contains(":names:_default'") && !script.contains(":profile:_default'"), "{script}");
        assert!(script.contains("'*::names -- Profile names.:_tool_profiles'"), "with a help text too: {script}");
        assert!(script.contains(":path:_default'"), "other arguments keep theirs: {script}");
    }

    #[test]
    fn bash_profile_commands_are_hooked() {
        let script = script(Shell::Bash, &mut command()).unwrap();
        assert!(
            script
                .contains("tool__subcmd__connect|tool__subcmd__log|tool__subcmd__secret__subcmd__set) _tool_profiles"),
            "{script}"
        );
        assert!(script.contains("--config|--key|-k) return 1 ;;"), "{script}");
    }

    /// zsh only tells arguments apart by their id: one shared with an
    /// argument that is not a profile would get the profiles too.
    #[test]
    fn zsh_refuses_a_profile_id_used_by_another_argument() {
        let mut tool = command().subcommand(Command::new("rename").arg(Arg::new("names")));
        let err = script(Shell::Zsh, &mut tool).unwrap_err();
        assert!(err.to_string().contains("4 zsh argument lines for 3 profile arguments"), "{err}");
    }

    #[test]
    fn a_tree_without_profile_arguments_is_refused() {
        assert!(script(Shell::Bash, &mut Command::new("tool").subcommand(Command::new("x"))).is_err());
    }
}
