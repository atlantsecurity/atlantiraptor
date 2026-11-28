import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { orgNameProblem, type Org } from './model.ts';

const orgs: Org[] = [
  { id: 'root', name: '<root>', root: true, users: 2 },
  { id: 'O1', name: 'Customer A', users: 1 },
];

describe('orgNameProblem', () => {
  it('accepts a new name', () => assert.equal(orgNameProblem('Customer B', orgs), ''));
  it('requires a name', () => assert.notEqual(orgNameProblem('   ', orgs), ''));
  it('refuses duplicates case-insensitively', () => assert.notEqual(orgNameProblem(' customer a ', orgs), ''));
  it('lets an org keep its own name', () => assert.equal(orgNameProblem('customer a', orgs, 'O1'), ''));
  it('refuses control characters', () => assert.notEqual(orgNameProblem('a\tb', orgs), ''));
  it('refuses long names', () => assert.notEqual(orgNameProblem('x'.repeat(101), orgs), ''));
});
