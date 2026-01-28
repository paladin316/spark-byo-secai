# SPARK Branding Guidelines

SPARK (Powered by BYO-SECAI) uses **two distinct but related branding layers**: one for the **GitHub project** and one for the **product UI**. This separation is intentional and ensures clarity, professionalism, and long-term consistency as the project evolves.

These guidelines exist to prevent branding drift and to make future contributions predictable and aligned.

---

## Branding Philosophy

> **GitHub presents SPARK the concept.  
> The product presents SPARK the tool.**

SPARK prioritizes **analyst clarity over visual noise**. Branding should reinforce trust, orientation, and purpose — never distract from analysis or decision-making.

---

## 1. GitHub / Project Branding

### Purpose
- Establish credibility and professionalism
- Clearly communicate *what SPARK is and why it exists*
- Support documentation, diagrams, and conceptual understanding

### Audience
- Analysts evaluating the project
- Security engineers and contributors
- Hiring managers and technical reviewers

### Characteristics
- Minimal and neutral
- Documentation-friendly
- High contrast, low decoration
- Suitable for Markdown and diagrams

### Approved Assets
- **Primary SPARK logo**
- Wordmark
- Architecture diagrams
- Process lifecycle diagrams
- README headers and section visuals

### Usage Locations
- `README.md`
- `/docs/**`
- `/assets/branding/github/`
- Architecture and process diagrams

### Restrictions
- Do **not** use UI-specific icons or glyphs
- Do **not** use dark-mode UI treatments
- Avoid decorative or animated branding

---

## 2. Product / Application Branding

### Purpose
- Subtle identity reinforcement during daily use
- Orientation within the UI
- Maintain a professional, analyst-first environment

### Audience
- Analysts using SPARK for active research
- Detection engineers and incident responders

### Characteristics
- Restrained and unobtrusive
- Dark-mode friendly
- Icon-driven
- Consistent and repeatable

### Approved Assets
- **Tertiary SPARK icon / glyph**
- UI color tokens
- Small header or sidebar icons
- Favicons or compact marks

### Usage Locations
- SPARK UI
- Navigation elements
- Headers and footers within the app
- `SPARK_v1_2/assets/branding/product/`

### Restrictions
- Do **not** use the primary logo in the UI
- Avoid large logos or banner-style branding
- Branding must never compete with data or analysis views

---

## Color Usage

- **GitHub / Docs:** Neutral, high-contrast colors suitable for light backgrounds
- **Product UI:** Tokenized colors designed for dark mode and long analysis sessions

Color definitions used in the product should be treated as **UI tokens**, not ad-hoc styling.

---

## Enforcement Rules (Source of Truth)

- GitHub branding assets live outside the product runtime
- Product branding assets live inside the application directory
- If an asset must exist in both places, **GitHub assets are the source of truth**
- Product assets should be optimized derivatives, not duplicates

---

## Future Additions

If new branding assets are introduced:
- Decide **which layer they belong to first**
- Avoid dual-use assets unless strictly necessary
- Update this document to reflect the change

---

## Summary

SPARK branding exists to support **clarity, trust, and analyst focus**.

Minimalism is a feature.  
Restraint is intentional.  
Consistency is non-negotiable.
