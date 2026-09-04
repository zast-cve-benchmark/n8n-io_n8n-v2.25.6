---
id: "GHSA-hv7x-3x78-gx53"
category: "incorrect-authorization"
cwe_ids: ["CWE-863"]
severity: "medium"
refs:
  - url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-hv7x-3x78-gx53"
    type: ADVISORY
    conclusion: |-
      n8n's `POST /workflows/{workflowId}/test-runs/new` endpoint (full prefix `/rest/workflows`) authorizes with `workflow:read` instead of `workflow:execute`, allowing an authenticated user with only read permission to trigger a real evaluation test run that actually executes the workflow through the internal workflow runner, which may cause unexpected outbound API calls, data changes, or other side effects on downstream systems. Fixed in n8n 1.123.55, 2.25.7, and 2.26.2 (OSV: GHSA-hv7x-3x78-gx53, Incorrect Authorization / CWE-863).

# Incorrect Authorization — POST /rest/workflows/:workflowId/test-runs/new

## Vulnerability Description

In n8n's POST /rest/workflows/:workflowId/test-runs/new (TestRunsController.create), the workflowId in the request path is passed to assertUserHasAccessToWorkflow(), which authorizes with the default workflow:read scope, and on success the code proceeds to call testRunnerService.startTestRun(), which executes the workflow under test with real datasets and credentials (runDatasetTrigger/runTestCase -> workflowRunner.run). Starting a test run is an operation that executes a workflow and should be gated by the workflow:execute scope, as required by the sibling handler cancelCase; here the guard's scope is too weak, so a project viewer or read-only sharer (PROJECT_VIEWER_SCOPES grants workflow:read but not workflow:execute) can trigger execution of workflows they are only allowed to read, and startTestRun performs no further re-check of execution permissions.

## Impact Scope

- Endpoint: `POST /rest/workflows/:workflowId/test-runs/new`

## Data Flow

1. `packages/cli/src/evaluation.ee/test-runs.controller.ee.ts:163`

   ```javascript
   const { workflowId } = req.params;
   ```
2. `packages/cli/src/evaluation.ee/test-runs.controller.ee.ts:165`

   ```javascript
   await this.assertUserHasAccessToWorkflow(workflowId, req.user);
   ```
3. `packages/cli/src/evaluation.ee/test-runs.controller.ee.ts:177`

   ```javascript
   const { testRun } = await this.testRunnerService.startTestRun(
   ```

## Evidence Code

```javascript
// packages/cli/src/evaluation.ee/test-runs.controller.ee.ts#L153-L173

		return { success: true };
	}

	@Post('/:workflowId/test-runs/new')
	async create(
		req: TestRunsRequest.Create,
		res: express.Response,
		@Body payload: StartTestRunRequestDto,
	) {
		const { workflowId } = req.params;

		await this.assertUserHasAccessToWorkflow(workflowId, req.user);

		const concurrency = payload.concurrency ?? 1;

		// Await the synchronous setup (workflow find + test-run row insert) so
		// the response carries the new `testRunId` and the FE can route to the
		// detail view without polling. The actual case-by-case execution is
		// detached inside `startTestRun` and exposed as `finished`, which we
		// intentionally discard here — fire-and-forget for the long-running
```

```javascript
// packages/cli/src/evaluation.ee/test-runs.controller.ee.ts#L155-L175
	}

	@Post('/:workflowId/test-runs/new')
	async create(
		req: TestRunsRequest.Create,
		res: express.Response,
		@Body payload: StartTestRunRequestDto,
	) {
		const { workflowId } = req.params;

		await this.assertUserHasAccessToWorkflow(workflowId, req.user);

		const concurrency = payload.concurrency ?? 1;

		// Await the synchronous setup (workflow find + test-run row insert) so
		// the response carries the new `testRunId` and the FE can route to the
		// detail view without polling. The actual case-by-case execution is
		// detached inside `startTestRun` and exposed as `finished`, which we
		// intentionally discard here — fire-and-forget for the long-running
		// part is preserved. `startTestRun` clamps `concurrency` against the
		// effective limit (env override → license tier default), so callers
```

```javascript
// packages/cli/src/evaluation.ee/test-runs.controller.ee.ts#L167-L185
		const concurrency = payload.concurrency ?? 1;

		// Await the synchronous setup (workflow find + test-run row insert) so
		// the response carries the new `testRunId` and the FE can route to the
		// detail view without polling. The actual case-by-case execution is
		// detached inside `startTestRun` and exposed as `finished`, which we
		// intentionally discard here — fire-and-forget for the long-running
		// part is preserved. `startTestRun` clamps `concurrency` against the
		// effective limit (env override → license tier default), so callers
		// can request more than the instance allows without erroring.
		const { testRun } = await this.testRunnerService.startTestRun(
			req.user,
			workflowId,
			concurrency,
		);

		res.status(202).json({ success: true, testRunId: testRun.id });
	}
}
```

## Root Cause

`missing-control`

## Exploit Steps

As a project-viewer user (workflow:read, no workflow:execute) authenticated against a shared project, POST /rest/workflows/<workflowId>/test-runs/new with the target workflow's id; observe the workflow executing under test despite lacking workflow:execute.
