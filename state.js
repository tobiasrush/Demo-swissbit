/**
 * @class State
 * @description     A class to manage the state of the application that dispatches an event when the state changes (poor man's React)
 * @param           {object}    initialState    The initial state of the application
 * @returns         {Proxy}                     A Proxy object that allows for the management of the application state (special sauce for the event dispatch)
 * @notes           This class is used to manage the state of the application. It is included here for convenince
 * @                and SHOULD NOT BE INCLUDED in any live/production implementations.
 */
class State {
    constructor(initialState = {}) {
        Object.assign(this, initialState);

        this.setCleanState = (baseState) => {
            Object.defineProperty(this, "cleanState", {
                value        : { ...baseState },
                writable     : true,
                configurable : true,
                enumerable   : false
            });
        }

        // Keep a pristine snapshot; make it non-enumerable so it doesn't leak into UI loops
        if(initialState){
            this.setCleanState(initialState);
        }

        return new Proxy(this, {
            get(target, key, receiver) {
                return Reflect.get(target, key, receiver);
            },

            // Core change handler
            set(target, key, value, receiver) {
                if(this.cleanState == null && key === "cleanState") {
                    this.setCleanState(value);
                    return true;
                }
                if (typeof key === "symbol" || key === "cleanState") return Reflect.set(target, key, value, receiver);

                const prev = Reflect.get(target, key, receiver);
                if (Object.is(prev, value)) return true;

                const ok = Reflect.set(target, key, value, receiver);
                if (ok)
                    document.dispatchEvent(new CustomEvent("stateChange", {detail : { key, value, previous: prev }}));
                return ok;
            },

            // Prop deletion should also announce a change
            deleteProperty(target, key) {
                if (key === "cleanState") return false;
                const had = Object.prototype.hasOwnProperty.call(target, key);
                const ok = Reflect.deleteProperty(target, key);
                if (had && ok)
                    document.dispatchEvent(new CustomEvent("stateChange", {detail: { key, value: undefined, deleted: true }}));
                return ok;
            }
        });
    }

    reset({ silent = true } = {}) {
        // Remove keys that aren't in the clean snapshot anymore
        for (const k of Object.keys(this)) {
            if (k === "cleanState") continue;
            if (!(k in this.cleanState)) delete this[k];
        }
        // Restore clean values
        Object.assign(this, this.cleanState);

        if (!silent) {
            document.dispatchEvent(new CustomEvent("stateChange", {detail: { ...this.cleanState, reset: true }}));
        }
        return true;
    }
}
