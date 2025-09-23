# httpjail Documentation

This directory contains the mdBook-based documentation for httpjail.

## Setup

mdBook is already installed. If you need to reinstall:

```bash
cargo install mdbook
```

## Development

To work on the documentation locally:

```bash
# Serve with auto-reload (default port 3000)
mdbook serve

# Or specify a custom port
mdbook serve --port 8080

# Build static files
mdbook build
```

The documentation will be available at `http://localhost:3000`.

## Structure

- `docs/` - Source markdown files
- `book/` - Built static HTML (git-ignored)
- `book.toml` - mdBook configuration
- `.github/workflows/docs.yml` - GitHub Actions for automatic deployment

## Adding Content

1. Add your markdown file to the appropriate directory in `docs/`
2. Update `docs/SUMMARY.md` to include your new page
3. Test locally with `mdbook serve`
4. Commit and push - GitHub Actions will deploy automatically

## Writing Guidelines

### Documentation Philosophy

- **Keep it minimal** - Focus on the UX surface of the tool, not implementation details
- **Minimal examples** - Show just enough to demonstrate the feature, not comprehensive tutorials
- **We're not teaching programming** - Assume users know how to write code in their language of choice
- **Focus on httpjail-specific behavior** - Document what the tool does, not general programming concepts

### Avoid Content Repetition

- **Don't duplicate content across pages** - Instead, link to the canonical source
- **Comparisons belong in overview pages** - Engine comparisons should be in the Rule Engines index, not repeated in each engine's guide
- **Common concepts should be centralized** - Debugging, performance tips, and other shared topics should have their own pages
- **Use cross-references liberally** - Link to related content rather than repeating it

## Deployment

Documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch. The workflow:

1. Builds the documentation using mdBook
2. Deploys to GitHub Pages
3. Available at: https://coder.github.io/httpjail/

## Resources

- [mdBook Documentation](https://rust-lang.github.io/mdBook/)
- [mdBook GitHub](https://github.com/rust-lang/mdBook)
- [CommonMark Spec](https://commonmark.org/) (Markdown standard)
