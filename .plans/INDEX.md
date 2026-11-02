# Project Resync Plans Bump Version

> [!IMPORTANT]
> **This file is auto generated.** To regenerate it, run `openlanes index`.
> Editing it by hand lasts until the next `resync dirs` renames a folder.

## Current specifications and their status


## 002.00 — ⭐ Encrypt Write Flag

<table>
  <thead>
    <tr>
      <th align="left">Status</th>
      <th align="left">Pull Requests</th>
      <th align="left">What it is</th>
      <th align="left">Artifacts</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td valign="top">⭐&nbsp;Planned</td>
      <td valign="top"><em>—</em></td>
      <td valign="top"><p>Today to encrypt or decrypt a file you must pass the file name, and <code>-o output-file-name</code>. However, there is a relationship between encrypted file names and non-encrypted:</p><p>Typically, encrypting <code>.env</code> results in <code>.env.encrypted</code>.</p></td>
      <td valign="top"><ul><li><a href="002.00%E2%94%81%E2%94%81%E2%AD%90%E2%94%81%E2%94%81%E2%9D%AFencrypt-write-flag/spec.md">Spec</a></li><li><a href="002.00%E2%94%81%E2%94%81%E2%AD%90%E2%94%81%E2%94%81%E2%9D%AFencrypt-write-flag/plan.md">Plan</a></li></ul></td>
    </tr>
  </tbody>
</table>


## 003.00 — ⚪ Sopsy Caching Agent

<table>
  <thead>
    <tr>
      <th align="left">Status</th>
      <th align="left">Pull Requests</th>
      <th align="left">What it is</th>
      <th align="left">Artifacts</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td valign="top">⚪&nbsp;New</td>
      <td valign="top"><em>—</em></td>
      <td valign="top"><p>A per-user <code>sopsy agent</code> that lets a developer authenticate once at the start of the day and then decrypt without re-authenticating, in any worktree. Today every decrypt costs a hardware gesture: Touch ID for the Secure Enclave, or a PIN and touch for a YubiKey.</p><p>The user&#39;s model:</p></td>
      <td valign="top"><ul><li><a href="003.00%E2%94%81%E2%94%81%E2%9A%AA%E2%94%81%E2%94%81%E2%9D%AFsopsy-caching-agent/spec.md">Spec</a></li><li><a href="003.00%E2%94%81%E2%94%81%E2%9A%AA%E2%94%81%E2%94%81%E2%9D%AFsopsy-caching-agent/state.json">state.json</a></li></ul></td>
    </tr>
  </tbody>
</table>


---

2 plans &nbsp; ⭐ 1 &nbsp; ⚪ 1
