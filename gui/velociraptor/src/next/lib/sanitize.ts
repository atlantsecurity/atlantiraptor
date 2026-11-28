// Turns template HTML from the server into React elements, after a
// second sanitizing pass in the browser (the server already filters it
// with bluemonday, see NewBlueMondayPolicy in reporting/gui.go).
import parse, { type HTMLReactParserOptions } from 'html-react-parser';
import DOMPurify from 'dompurify';

export function sanitize(html: string): string {
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    CUSTOM_ELEMENT_HANDLING: {
      tagNameCheck: /^(notebook|grr|bar-chart|scatter-chart|time-chart|tool-viewer|velo)-/,
      attributeNameCheck: /^(value|params|base-url|adtype|caption|version|text|href|icon)$/,
      allowCustomizedBuiltInElements: true,
    },
  });
}

// React wants no whitespace text between table elements.
export function cleanupHTML(html: string): string {
  return html
    .replace(/>\s*<(\/?)(thead|tbody|tr|th|td)/g, '><$1$2');
}

export default function parseHTML(html: string, options?: HTMLReactParserOptions) {
  return parse(sanitize(cleanupHTML(html)), options);
}
