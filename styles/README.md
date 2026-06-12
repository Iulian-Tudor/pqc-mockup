<!-- 
SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and Iulian-Tudor Scutaru

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Styles Organization

The styles are now modularized for better maintainability. Here's the structure:

## Files

- **global.css** - Global variables, base styles, and layout
  - CSS custom properties (colors, spacing, animations)
  - Body, header, footer, main layout styles
  - Core animations

- **components/parameters.css** - Simulation parameter form styles
  - Parameter grid and input styling
  - Form options (checkboxes, selects)
  - Parameter sections and separators

- **components/buttons.css** - Button component styles
  - Primary and secondary button styling
  - Button hover and disabled states
  - Button group layout

- **components/output.css** - Simulation output section styles
  - Output container and header
  - Status indicator styling
  - Simulation log styling
  - Error messages

- **components/results.css** - Results visualization styles
  - Visualization container layout
  - Chart sections and containers
  - Results cards (user, document cards)
  - Download buttons and statistics

- **components/mode-selector.css** - Mode selector panel styles
  - Toggle button styling
  - Side panel layout and animations
  - Mode option cards
  - Backdrop overlay

## Import Order (in index.html)

CSS files are imported in this order for proper cascading:

1. global.css (base styles)
2. components/parameters.css
3. components/buttons.css
4. components/output.css
5. components/results.css
6. components/mode-selector.css

This ensures component styles override global styles appropriately.
