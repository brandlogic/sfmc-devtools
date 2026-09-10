/**
 * Convert the JSON records used in metadata/deployment reports into a table.
 * Preserve encounter order and traverse only own properties, including nested arrays.
 *
 * @param {object|object[]} records report records
 * @returns {any[][]} header row followed by value rows
 */
export default function jsonToTable(records) {
    const rows = Array.isArray(records) ? records : [records];
    const headers = new Map();
    const flattened = rows.map((row) => {
        const values = new Map();
        /**
         * Collect leaf values without interpreting property names as object paths.
         *
         * @param {any} value current value
         * @param {string[]} path own-property path
         * @returns {void} -
         */
        function visit(value, path) {
            if (value !== null && typeof value === 'object') {
                const entries = Object.entries(value);
                if (entries.length) {
                    for (const [key, child] of entries) {
                        visit(child, [...path, key]);
                    }
                    return;
                }
                if (!Array.isArray(value)) {
                    return;
                }
            }
            if (!path.length) {
                return;
            }
            const id = JSON.stringify(path);
            const label = path
                .map((key) => (path.length > 1 && key.includes('.') ? `\`${key}\`` : key))
                .join('.');
            headers.set(id, label);
            values.set(id, value === undefined ? '' : value);
        }
        visit(row, []);
        return values;
    });
    return [
        [...headers.values()],
        ...flattened.map((values) =>
            [...headers.keys()].map((key) => (values.has(key) ? values.get(key) : ''))
        ),
    ];
}
