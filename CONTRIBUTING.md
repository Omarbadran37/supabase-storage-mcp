# Contributing to Supabase Storage MCP

First off, thank you for considering contributing to the Supabase Storage MCP server! Your help is greatly appreciated.

## How Can I Contribute?

There are many ways to contribute, from writing tutorials or blog posts, improving the documentation, submitting bug reports and feature requests or writing code which can be incorporated into the main project.

### Reporting Bugs

- **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/USERNAME/supabase-storage-mcp/issues).
- If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/USERNAME/supabase-storage-mcp/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

- Open a new issue to discuss your enhancement. This allows us to coordinate and ensure that the enhancement fits with the project's goals.
- Be sure to provide a clear and detailed explanation of the feature you want and why it's important.

### Pull Requests

We love pull requests. Here's a quick guide:

1.  **Fork the repo** and create your branch from `main`.
2.  **Set up your development environment**:
    ```bash
    npm install
    ```
3.  **Add tests** for your changes. This is important so we don't break them in a future version.
4.  **Make your changes**. Please ensure your code follows the existing style.
5.  **Run the tests**:
    ```bash
    npm test
    ```
6.  **Ensure your code lints**.
7.  **Issue that pull request!**

## Development Setup

To get started with the codebase, fork the repo, then clone it locally:

```bash
git clone https://github.com/YOUR_USERNAME/supabase-storage-mcp.git
cd supabase-storage-mcp
```

Install the dependencies:

```bash
npm install
```

To run the server in development mode (which will watch for changes):

```bash
npm run dev
```

## Testing

We use `vitest` for testing. To run the full test suite:

```bash
npm test
```

Please add tests for any new features or bug fixes. This helps us maintain a high level of quality.

## Coding Conventions

-   Follow the existing code style.
-   Add comments to your code where necessary.
-   Ensure that your code is well-documented, especially for new features.

## Submitting a Pull Request

-   Keep your PRs focused. It's better to open multiple small PRs than one large one.
-   Provide a clear and descriptive title for your PR.
-   In the PR description, explain the "why" behind your changes.
-   Link to any relevant issues.

Thank you for your contribution!
