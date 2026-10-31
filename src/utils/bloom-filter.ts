/**
 * Bloom Filter for Deduplication - DSA Implementation
 * ====================================================
 */

export default class BloomFilter {
    size: number;
    numHashes: number;
    bits: Uint8Array;
    itemCount: number;
    checks: number;
    positives: number;

    constructor(expectedItems: number = 100000, falsePositiveRate: number = 0.01) {
        this.size = Math.ceil(
            -(expectedItems * Math.log(falsePositiveRate)) / Math.pow(Math.log(2), 2)
        );

        this.numHashes = Math.ceil((this.size / expectedItems) * Math.log(2));
        this.bits = new Uint8Array(Math.ceil(this.size / 8));
        this.itemCount = 0;
        this.checks = 0;
        this.positives = 0;
    }

    getHashPositions(item: string): number[] {
        let h1 = 5381;
        let h2 = 0;

        for (let i = 0; i < item.length; i++) {
            const char = item.charCodeAt(i);
            h1 = ((h1 << 5) + h1) ^ char;
            h2 = char + (h2 << 6) + (h2 << 16) - h2;
        }

        h1 = Math.abs(h1);
        h2 = Math.abs(h2) | 1;

        const positions: number[] = [];
        for (let i = 0; i < this.numHashes; i++) {
            positions.push((h1 + i * h2) % this.size);
        }

        return positions;
    }

    getBit(position: number): boolean {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        return (this.bits[byteIndex] & (1 << bitIndex)) !== 0;
    }

    setBit(position: number): void {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        this.bits[byteIndex] |= (1 << bitIndex);
    }

    add(item: string): void {
        const positions = this.getHashPositions(item);
        for (const pos of positions) {
            this.setBit(pos);
        }
        this.itemCount++;
    }

    check(item: string): boolean {
        this.checks++;
        const positions = this.getHashPositions(item);
        const result = positions.every((pos) => this.getBit(pos));

        if (result) {
            this.positives++;
        }

        return result;
    }

    checkAndAdd(item: string): boolean {
        const positions = this.getHashPositions(item);
        const exists = positions.every((pos) => this.getBit(pos));

        if (!exists) {
            for (const pos of positions) {
                this.setBit(pos);
            }
            this.itemCount++;
        }

        this.checks++;
        if (exists) {
            this.positives++;
        }

        return exists;
    }

    getStats() {
        const fillRatio = (this.itemCount * this.numHashes) / this.size;
        const estimatedFP = Math.pow(1 - Math.exp(-fillRatio), this.numHashes);

        return {
            sizeBits: this.size,
            sizeBytes: this.bits.length,
            numHashes: this.numHashes,
            itemsAdded: this.itemCount,
            checks: this.checks,
            positives: this.positives,
            fillRatio,
            estimatedFalsePositiveRate: estimatedFP,
        };
    }

    toBase64(): string {
        return Buffer.from(this.bits).toString('base64');
    }

    static fromBase64(data: string, expectedItems: number, falsePositiveRate: number): BloomFilter {
        const filter = new BloomFilter(expectedItems, falsePositiveRate);
        const decoded = Buffer.from(data, 'base64');
        filter.bits = new Uint8Array(decoded);
        return filter;
    }
}

