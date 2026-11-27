---
title: Preferences and keyboard shortcuts
description: Personal settings in the Atlantiraptor console - theme, time zone, language, download password - and keyboard shortcuts.
---

## Settings

Open the account menu (top right) and choose **Settings…**:

| Setting | Effect |
|---|---|
| **Theme** | Light or dark, plus several alternative themes. The account menu's light/dark switch is a shortcut for the two main ones. |
| **Display time zone** | Times in tables and timelines are shown in this zone. Stored data is always UTC. |
| **Language** | English, Deutsch, Español, Français, 日本語, Português, Tiếng Việt. New Atlantiraptor screens are in English. |
| **Downloads password** | A default password for password-protected zip exports (see below). |
| **Organization** | The organization you work in (also in the account menu). |

Settings are stored with your user on the server, so they follow you to
another browser.

## The downloads password

Evidence often contains malware. When you export a collection or hunt as a
password-protected zip, Atlantiraptor uses your **downloads password**, so
that antivirus on your workstation does not delete or quarantine the
download, and the zip can be stored safely. Set it once in Settings; the
export dialogs then offer **Password-protect the zip**. The usual
convention is `infected`; any password works.

## Password and two-factor sign in

**Password and two-factor…** in the account menu changes your password and
sets up two-factor sign in. See [Authentication](/deployment/authentication/#two-factor-sign-in).

## Keyboard shortcuts

| Keys | Where | Does |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>K</kbd> / <kbd>⌘</kbd>+<kbd>K</kbd> | Anywhere | Command palette |
| <kbd>Ctrl</kbd>+<kbd>/</kbd> | Anywhere | List of keyboard shortcuts (also **Keyboard shortcuts** in the account menu) |
| <kbd>/</kbd> | Lists (hunts, artifacts) | Focus the filter box |
| <kbd>J</kbd> / <kbd>K</kbd>, <kbd>↓</kbd> / <kbd>↑</kbd> | Hunts | Next / previous hunt |
| <kbd>N</kbd> | Hunts | New hunt |
| <kbd>Esc</kbd> | Dialogs, palette | Close |
| <kbd>Ctrl</kbd>+<kbd>Enter</kbd> | Notebook and artifact editors | Save / run |
| <kbd>Ctrl</kbd>+<kbd>,</kbd> | Code editors | Editor settings (key bindings, font size) |
| <kbd>Alt</kbd>+<kbd>D</kbd> | Anywhere | Go to the dashboard |
| <kbd>Alt</kbd>+<kbd>N</kbd> | Anywhere | Go to notebooks |

The list shows further shortcuts for collection and artifact screens.

## Customizing the console for everyone

Administrators can add links to the sidebar (for example your runbooks or
ticketing system) with `GUI.links` in the [server configuration](/deployment/configuration/):

```yaml
GUI:
  links:
    - text: Runbooks
      url: https://wiki.example.com/soc/runbooks
      new_tab: true
      type: sidebar
```

Each link can have an `icon_url` (an image or a `data:` URL). Set
`disabled: true` on an entry to hide a default link.
