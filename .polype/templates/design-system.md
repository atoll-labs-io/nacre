# Design system — <project>

Written by `/po-design-system`; change it by running that command again, not by hand.

## Sources
- Visual direction: <what the user supplied — brand guide, logo and palette, a product or site to follow, mockups — or "none">
- System in the base: <theme or token files, UI component folder, with their paths — or "none">
- Profile: <the boilerplate profile's UI inventory used as a starting point — or "none">

## Tokens

| Token | Role | Light | Dark | Defined at |
| --- | --- | --- | --- | --- |
| <name> | <text, surface, border, accent, focus…> | <value> | <value, or "missing" → Gaps> | <path:line> |

## Contrast

| Text | Surface | Theme | Ratio | Needed | Result | Fix |
| --- | --- | --- | --- | --- | --- | --- |
| <text token> | <surface token> | <light or dark> | <n.nn:1> | <4.5:1 or 3:1> | <pass or fail> | <before → after, or —> |

## Components

| Component | Path | Variants | States |
| --- | --- | --- | --- |
| <name> | <path> | <variants> | <states it handles> |

## State patterns
- Empty: <how it looks, which components carry it>
- Loading: <…>
- Error: <…>
- Success: <…>
- Disabled: <…>
- Focus: <…>

## Do / Don't

Do:
- <a rule drawn from the inventory>

Don't:
- <a rule drawn from the inventory>

## Gaps
- <what the system lacks — a token without a dark value, a missing state, a missing component — left for a person to decide, never filled by invention>
