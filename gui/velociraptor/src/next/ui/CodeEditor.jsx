// Code editor (Ace) with VQL, YAML, Markdown, Sigma, regex and YARA
// highlighting. The user's editor preferences (key bindings, font size,
// ...) are saved to their profile when the editor loses focus. Loaded
// lazily so pages without an editor don't pay for Ace.
import React, { useMemo } from 'react';
import AceEditor from 'react-ace';
import 'ace-builds';
import ace from 'ace-builds/src-noconflict/ace.js';
import 'ace-builds/src-min-noconflict/ext-language_tools.js';
import 'ace-builds/src-min-noconflict/ext-searchbox.js';
import 'ace-builds/src-min-noconflict/ext-settings_menu.js';
import 'ace-builds/src-min-noconflict/ext-options.js';
import 'ace-builds/src-min-noconflict/theme-github.js';
import 'ace-builds/src-min-noconflict/theme-xcode.js';
import 'ace-builds/src-min-noconflict/theme-vibrant_ink.js';
import 'ace-builds/src-min-noconflict/keybinding-emacs.js';
import 'ace-builds/src-min-noconflict/keybinding-sublime.js';
import 'ace-builds/src-min-noconflict/keybinding-vim.js';
import 'ace-builds/src-min-noconflict/keybinding-vscode.js';
import 'ace-builds/src-min-noconflict/mode-json.js';
import 'ace-builds/src-min-noconflict/mode-sql.js';
// The custom modes below extend these built-in ones.
import 'ace-builds/src-min-noconflict/mode-yaml.js';
import 'ace-builds/src-min-noconflict/mode-markdown.js';
import VqlMode from './ace/mode-vql.jsx';
import MarkdownMode from './ace/mode-markdown.jsx';
import YamlMode from './ace/mode-yaml.jsx';
import SigmaMode from './ace/mode-sigma.jsx';
import RegexMode from './ace/mode-regex.jsx';
import YaraMode from './ace/mode-yara.jsx';
import './ace/ace.css';
import * as api from '../lib/api';
import { useTraits } from '../lib/queries';
import { isDarkTheme } from '../shell/theme';

const MODES = {
  vql: VqlMode, markdown: MarkdownMode, md: MarkdownMode, yaml: YamlMode,
  sigma: SigmaMode, regex: RegexMode, yara: YaraMode,
};

ace.config.set('basePath', '/');
for (const [name, Mode] of Object.entries(MODES)) ace.define(`ace/mode/${name}`, null, new Mode());

// Options the component controls; never taken from or saved to the
// user's preferences.
const OWN = new Set(['mode', 'theme', 'readOnly', 'minLines', 'maxLines', 'autoScrollEditorIntoView']);

function cleanOptions(o) {
  const out = {};
  for (const [k, v] of Object.entries(o || {})) if (v && !OWN.has(k)) out[k] = v;
  return out;
}

export default function CodeEditor({ value, onChange, mode = 'yaml', readOnly = false, minLines, maxLines, className, focus = false }) {
  const { traits, updateTraits } = useTraits();
  const userOptions = useMemo(() => {
    try { return cleanOptions(JSON.parse(traits?.ui_settings || '{}')); } catch { return {}; }
  }, [traits?.ui_settings]);

  const savePreferences = (_e, editor) => {
    const now = cleanOptions(editor?.getOptions?.());
    if (JSON.stringify(now) !== JSON.stringify(userOptions)) {
      api.post('v1/SetGUIOptions', { options: JSON.stringify(now) }).then(updateTraits).catch(() => undefined);
    }
  };

  return (
    <div className={'rx-code ' + (className || '')}>
      <AceEditor
        mode={MODES[mode] ? mode : 'sql'}
        theme={isDarkTheme(traits?.theme) ? 'vibrant_ink' : 'github'}
        value={value || ''}
        onChange={onChange}
        focus={focus}
        width="100%"
        showGutter
        setOptions={userOptions}
        editorProps={{ $blockScrolling: true }}
        onBlur={savePreferences}
        onLoad={editor => {
          const session = editor.getSession();
          session.setUseWorker(false);
          const Mode = MODES[mode];
          if (Mode) session.setMode(new Mode());
          editor.setReadOnly(!!readOnly);
          if (minLines) editor.setOption('minLines', minLines);
          if (maxLines) editor.setOption('maxLines', maxLines);
          editor.renderer.setShowPrintMargin(false);
          // Absolute line numbers always: saved preferences (vim mode)
          // can turn on relative numbers, which read oddly in a viewer.
          const fix = () => {
            editor.setOption('relativeLineNumbers', false);
            if (readOnly) {
              editor.setOption('highlightActiveLine', false);
              editor.setOption('highlightGutterLine', false);
              editor.renderer.$cursorLayer.element.style.display = 'none';
            }
          };
          fix();
          setTimeout(fix, 0);
        }}
      />
    </div>
  );
}
