import { assert } from 'chai';
import Auth from '../lib/util/auth.js';
import File from '../lib/util/file.js';
import { Util } from '../lib/util/util.js';
import * as testUtils from './utils.js';

describe('Authentication security integration', () => {
    const bu = {
        credential: 'testInstance',
        businessUnit: 'testBU',
        mid: 9999999,
        eid: 1111111,
    };

    beforeEach(() => {
        testUtils.mockSetup();
    });

    afterEach(() => {
        testUtils.mockReset();
    });

    it('clears initialized SDKs as well as persistent sessions', () => {
        const previous = Auth.getSDK(bu);
        Auth.clearSessions();
        assert.notStrictEqual(Auth.getSDK(bu), previous);
    });

    it('does not change the stored parent account when using a child BU', () => {
        const original = File.readJsonSync('.mcdev-auth.json');
        const child = Auth.getSDK(bu);
        const parent = Auth.getSDK({ ...bu, businessUnit: '_ParentBU_', mid: 1111111 });
        assert.equal(child.auth.authObject.account_id, 9999999);
        assert.equal(parent.auth.authObject.account_id, 1111111);
        assert.deepEqual(File.readJsonSync('.mcdev-auth.json'), original);
    });

    it('redacts request and response diagnostics at the SDK callbacks', () => {
        const sdk = Auth.getSDK(bu);
        const messages = [];
        const original = Util.logger.debug;
        Util.logger.debug = (message) => {
            messages.push(message);
            return Util.logger;
        };
        Util.OPTIONS.api = 'log';
        try {
            sdk.auth.options.eventHandlers.logRequest({
                headers: { authorization: 'Bearer topsecret' },
                data: { client_secret: 'topsecret' },
            });
            sdk.auth.options.eventHandlers.logResponse({
                data: { access_token: 'topsecret', name: 'retained' },
            });
            assert.notInclude(messages.join('\n'), 'topsecret');
            assert.include(messages.join('\n'), 'retained');
        } finally {
            Util.logger.debug = original;
        }
    });
});
