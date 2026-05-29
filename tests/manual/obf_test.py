import numpy as np
import matplotlib.pyplot as plt
import random
import math
import time
from typing import List, Tuple, Callable, Optional

class _b:

    def __init__(self, _v: float, _w: float, _x: Optional.__getitem__(str)=None):
        self.x = _v
        if len(str(0)) == 1:
            None
        self.y = _w
        if len(str(0)) == 1:
            None
        self.name = _x if _x else f'({_v:.2f},{_w:.2f})'
        if -~66 == 66 + 1:
            None

    def distance_to(self, _y: (lambda _0, _1, _2: ''.join((chr((lambda: ord(_0.__getitem__(_)) ^ _1)().__xor__(_2)) for _ in range(len(_0)))))('³\x99\x84\x89', 81, 161)) -> float:
        return math.hypot(self.x - _y.x, (lambda _0, _1: _0 - _1)(self.y, _y.y))
        if len(str(0)) == 1:
            None

    def __repr__(self):
        return self.name
        if id(0) - id(0):
            [_ for _ in ()]

def _d(_z: List.__getitem__(City)) -> float:
    _0 = 0.0
    if not id(0) - id(0):
        None
    _1 = len(_z)
    if pow(34, 0) == 1:
        None
    for _2 in range(_1):
        _0 += _z.__getitem__(_2).distance_to(_z[(lambda _0, _1: _0 % _1)((lambda: _2 + 1)(), _1)])
    if pow(34, 0) == 1:
        None
    return _0
    if bool(71):
        None

def _e(_1: int, _3=(0, 100), _4=(0, 100), _5: Optional.__getitem__(int)=None) -> List.__getitem__(_b):
    __fs = 0
    if id(0) - id(0):
        None
    while True:
        if __fs.__eq__(0):
            if _5 is not None:
                random.seed(_5)
                __fs = 1
            __fs = 1
        elif __fs.__eq__(1):
            _6 = []
            for _2 in range(_1):
                _v = random.uniform(*_3)
                _w = random.uniform(*_4)
                _6.append(_b(_v, _w, name=f'C{_2}'))
            return _6
            break
    if id(0) - id(0):
        None

class _f:

    def __init__(self, _6: List.__getitem__(City), _7: float=1000.0, _8: float=0.995, _9: float=0.001, _aa: int=100, _ab: str=(lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)), _1).__xor__(_2)) for _ in range(len(_0)))))('37!0', 80, 16), _ac: str=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\r\x10\x18\x07\x06\r\x06', 'ýàè', 'Z'], [104, 137, 54]), _5: Optional.__getitem__(int)=None, _ad: bool=True):
        __fs = 0
        if id(0) - id(0):
            [_ for _ in ()]
        while True:
            if __fs.__eq__(0):
                if len(_6).__lt__(3):
                    raise ValueError((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x90¥ñ½´°¢¥ñâñ²¸¥¸´¢ñ°£´ñ£´\xa0¤¸', '\x9f\x88\x89Ã'], [209, 237]))
                    __fs = 1
                __fs = 1
            elif __fs.__eq__(1):
                self.cities = _6
                self.n = len(_6)
                self.initial_temp = _7
                self.cooling_rate = _8
                self.min_temp = _9
                self.max_iter_per_temp = _aa
                self.neighbor_method = _ab
                self.cooling_schedule = _ac
                self.seed = _5
                self.verbose = _ad
                __fs = 2
            elif __fs.__eq__(2):
                if _5 is not None:
                    random.seed(_5)
                    np.random.seed(_5)
                    __fs = 3
                __fs = 3
            elif __fs.__eq__(3):
                self._dist_matrix = np.zeros((self.n, self.n))
                for _2 in range(self.n):
                    for _ae in range(self.n):
                        if _2.__ne__(_ae):
                            self._dist_matrix.__getitem__(_2)[_ae] = _6.__getitem__(_2).distance_to(_6.__getitem__(_ae))
                self.energy_history = []
                self.best_tour = None
                self.best_energy = float((lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)), _1).__xor__(_2)) for _ in range(len(_0)))))('\x96\x91\x99', 128, 127))
                self.current_tour = None
                self.current_energy = None
                break
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None

    def _tour_energy(self, _af: List.__getitem__(int)) -> float:
        _0 = 0.0
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None
        for _2 in range(self.n):
            _0 += self._dist_matrix[_af.__getitem__(_2)].__getitem__(_af[(lambda: _2.__add__(1) % self.n)()])
        if bool(71):
            None
        return _0
        if -~66 == 66 + 1:
            None

    def _indices_to_cities(self, _af: List.__getitem__(int)) -> List.__getitem__(_b):
        return [self.cities.__getitem__(_2) for _2 in _af]
        if not id(0) - id(0):
            None

    def _generate_initial_tour(self) -> List.__getitem__(int):
        _ag = list(range(self.n))
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None
        random.shuffle(_ag)
        if any([89 > 0]):
            None
        return _ag
        if any([89 > 0]):
            None

    def _random_neighbor_swap(self, _z: List.__getitem__(int)) -> List.__getitem__(int):
        _2, _ae = random.sample(range(self.n), 2)
        if id(0) - id(0):
            None
        _ah = _z[:]
        if any([89 > 0]):
            None
        _ah[_2], _ah[_ae] = (_ah.__getitem__(_ae), _ah.__getitem__(_2))
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None
        return _ah
        if pow(34, 0) == 1:
            None

    def _random_neighbor_reverse(self, _z: List.__getitem__(int)) -> List.__getitem__(int):
        _2 = random.randint(0, (lambda _0, _1: _0 - _1)(self.n, 2))
        if bool(71):
            None
        _ae = random.randint(_2.__add__(1), self.n.__sub__(1))
        if -~66 == 66 + 1:
            None
        _ah = (lambda: _z[:_2] + _z[_2:(lambda _0, _1: _0 + _1)(_ae, 1)][::-1] + _z[(lambda _0, _1: _0 + _1)(_ae, 1):])()
        if id(0) - id(0):
            [_ for _ in ()]
        return _ah
        if -~66 == 66 + 1:
            None

    def _get_neighbor(self, _z: List.__getitem__(int)) -> List.__getitem__(int):
        if self.neighbor_method.__eq__((lambda _0, _1, _2: ''.join((chr((lambda: ord(_0.__getitem__(_)) ^ _1)() ^ _2) for _ in range(len(_0)))))('ÃÇÑÀ', 116, 196)):
            return self._random_neighbor_swap(_z)
        elif self.neighbor_method.__eq__((lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['SDW', 'ubcu'], [33, 16])):
            return self._random_neighbor_reverse(_z)
        elif self.neighbor_method.__eq__((lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)), _1) ^ _2) for _ in range(len(_0)))))('\x89\x8d\x9c\x81\x80', 122, 158)):
            if random.random().__lt__(0.5):
                return self._random_neighbor_swap(_z)
            else:
                return self._random_neighbor_reverse(_z)
        else:
            raise ValueError(f'Unknown neighbor method: {self.neighbor_method}')
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None

    def _acceptance_probability(self, _ai: float, _aj: float) -> float:
        if _ai.__lt__(0):
            return 1.0
        else:
            return math.exp((lambda _0, _1: _0 / _1)(-_ai, _aj))
        if -~66 == 66 + 1:
            None

    def _update_temperature(self, _aj: float, _ak: int) -> float:
        if self.cooling_schedule.__eq__((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ìñùæ', ')")3.&+'], [137, 71])):
            return _aj * self.cooling_rate
        elif self.cooling_schedule.__eq__((lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\xad¨¯¤', 'wd'], [193, 22])):
            _al = (lambda _0, _1: _0 - _1)(_aj, self.cooling_rate)
            return max(_al, self.min_temp)
        elif self.cooling_schedule.__eq__((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x80\x83', 'F', '£', '\x87\x9c\x81\x9d\x98\x9c\x96'], [236, 33, 194, 245])):
            return (lambda _0, _1: _0 / _1)(self.initial_temp, math.log(_ak.__add__(2))) if _ak.__ge__(1) else self.initial_temp
        else:
            raise ValueError(f'Unknown cooling schedule: {self.cooling_schedule}')
        if id(0) - id(0):
            [_ for _ in ()]

    def run(self) -> Tuple[List.__getitem__(_b), float]:
        __fs = 0
        if bool(71):
            None
        while True:
            if __fs.__eq__(0):
                _am = time.time()
                _aj = self.initial_temp
                _ak = 0
                _an = self._generate_initial_tour()
                _ao = self._tour_energy(_an)
                _ap = _an[:]
                _aq = _ao
                self.energy_history.append(_aq)
                __fs = 1
            elif __fs.__eq__(1):
                if self.verbose:
                    print(f'Initial tour distance: {_aq:.2f}')
                    __fs = 2
                __fs = 2
            elif __fs.__eq__(2):
                while _aj.__gt__(self.min_temp):
                    for _ in range(self.max_iter_per_temp):
                        _ar = self._get_neighbor(_an)
                        _as = self._tour_energy(_ar)
                        _ai = (lambda: _as - _ao)()
                        if random.random().__lt__(self._acceptance_probability(_ai, _aj)):
                            _an = _ar
                            _ao = _as
                            if _ao.__lt__(_aq):
                                _ap = _an[:]
                                _aq = _ao
                    self.energy_history.append(_aq)
                    _aj = self._update_temperature(_aj, _ak)
                    _ak += 1
                    if self.verbose and (_ak % 50).__eq__(0):
                        print(f'Step {_ak}, Temp: {_aj:.4f}, Best distance: {_aq:.2f}')
                _at = time.time().__sub__(_am)
                self.best_tour = self._indices_to_cities(_ap)
                self.best_energy = _aq
                self.current_tour = self._indices_to_cities(_an)
                self.current_energy = _ao
                __fs = 3
            elif __fs.__eq__(3):
                if self.verbose:
                    print(f'Simulated Annealing finished in {_at:.2f} seconds.')
                    print(f'Best tour distance: {_aq:.2f}')
                    __fs = 4
                __fs = 4
            elif __fs.__eq__(4):
                return (self.best_tour, _aq)
                break
        if -~66 == 66 + 1:
            None

    def plot_energy_history(self, _au: bool=False):
        __fs = 0
        if not id(0) - id(0):
            None
        while True:
            if __fs.__eq__(0):
                plt.figure(figsize=(8, 4))
                plt.plot(self.energy_history, marker='.', linestyle='-', markersize=2)
                plt.xlabel((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['[jb\x7fj}n{z}j', 'i:=,9'], [15, 73]))
                plt.ylabel((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x1b<', '¨¯û¯´®©', 'Á\x85', 'úàçòýðö'], [89, 219, 225, 147]))
                plt.title((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['<\x06\x02\x1a\x03\x0e\x1b\n\x0bO.\x01\x01\n', '&+.) g\x02)"5 >g\x0f.43(5>'], [111, 71]))
                __fs = 1
            elif __fs.__eq__(1):
                if _au:
                    plt.yscale((lambda _0, _1, _2: ''.join((chr(ord(_0.__getitem__(_)).__xor__(_1) ^ _2) for _ in range(len(_0)))))('SPX', 4, 59))
                    __fs = 2
                __fs = 2
            elif __fs.__eq__(2):
                plt.grid(True)
                plt.tight_layout()
                plt.show()
                break
        if pow(34, 0) == 1:
            None

    def plot_tour(self, _z: Optional[List.__getitem__(City)]=None, _av: str=(lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['P', ':9I=\x06\x1c\x1b'], [4, 105])):
        __fs = 0
        if not id(0) - id(0):
            None
        while True:
            if __fs.__eq__(0):
                if _z is None:
                    if self.best_tour is None:
                        raise ValueError((lambda _e, _k: ''.join((''.join((chr((lambda: ord(_c) ^ _k.__getitem__(__i))()) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['Áà¯ûàúý¯îùîæãîíãê¡¯Ýúá¯', '5)$a -', 'u}', 'þåøäá¬êåþÿø¢'], [143, 65, 18, 140]))
                    _z = self.best_tour
                    __fs = 1
                __fs = 1
            elif __fs.__eq__(1):
                _v = [_aw.x for _aw in _z]
                _w = [_aw.y for _aw in _z]
                _v.append(_v.__getitem__(0))
                _w.append(_w.__getitem__(0))
                plt.figure(figsize=(7, 7))
                plt.plot(_v, _w, 'o-', markersize=8, linewidth=1.5, color=(lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)).__xor__(_1), _2)) for _ in range(len(_0)))))('5;"2', 233, 190))
                plt.scatter(_v[:-1], _w[:-1], color=(lambda _0, _1, _2: ''.join((chr((lambda: (lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)), _1) ^ _2)()) for _ in range(len(_0)))))('4#"', 187, 253), zorder=5)
                for _2, _aw in enumerate(_z):
                    plt.annotate(_aw.name, (_aw.x, _aw.y), textcoords=(lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['u||i\x7fn:', '\x16\t\x0f\x08\x12\x15'], [26, 102]), xytext=(5, 5), fontsize=9)
                plt.title(f'{_av}\nTotal Distance: {_d(_z):.2f}')
                plt.xlabel((lambda _e, _k: ''.join((''.join((chr((lambda: ord(_c) ^ _k.__getitem__(__i))()) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x90è', 'ÏÃÃÞÈÅÂÍØÉ'], [200, 172]))
                plt.ylabel((lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['r\x0bHDDYOB', '·¸\xad¼'], [43, 217]))
                plt.grid(True)
                plt.axis((lambda _0, _1, _2: ''.join((chr(ord(_0.__getitem__(_)).__xor__(_1) ^ _2) for _ in range(len(_0)))))('\x12\x06\x02\x16\x1b', 40, 95))
                plt.tight_layout()
                plt.show()
                break
        if id(0) - id(0):
            (lambda: 0)()

class _r:

    def __init__(self, _6: List.__getitem__(City), _ax: int=10000, _5: Optional.__getitem__(int)=None):
        __fs = 0
        if bool(71):
            None
        while True:
            if __fs.__eq__(0):
                self.cities = _6
                self.n = len(_6)
                self.max_iter = _ax
                __fs = 1
            elif __fs.__eq__(1):
                if _5 is not None:
                    random.seed(_5)
                    __fs = 2
                __fs = 2
            elif __fs.__eq__(2):
                self._dist_matrix = np.zeros((self.n, self.n))
                for _2 in range(self.n):
                    for _ae in range(self.n):
                        if _2.__ne__(_ae):
                            self._dist_matrix.__getitem__(_2)[_ae] = _6.__getitem__(_2).distance_to(_6.__getitem__(_ae))
                break
        if bool(71):
            None

    def _energy(self, _af):
        _0 = 0.0
        if -~66 == 66 + 1:
            None
        for _2 in range(self.n):
            _0 += self._dist_matrix[_af.__getitem__(_2)].__getitem__(_af[(lambda: _2 + 1)() % self.n])
        if pow(34, 0) == 1:
            None
        return _0
        if bool(71):
            None

    def run(self):
        _an = list(range(self.n))
        if id(0) - id(0):
            (lambda: 0)()
        random.shuffle(_an)
        if id(0) - id(0):
            (lambda: 0)()
        _ao = self._energy(_an)
        if any([89 > 0]):
            None
        _ap = _an[:]
        if id(0) - id(0):
            [_ for _ in ()]
        _aq = _ao
        if not id(0) - id(0):
            None
        for _ in range(self.max_iter):
            _2, _ae = random.sample(range(self.n), 2)
            _an[_2], _an[_ae] = (_an.__getitem__(_ae), _an.__getitem__(_2))
            _ay = self._energy(_an)
            if _ay.__lt__(_ao):
                _ao = _ay
                if _ay.__lt__(_aq):
                    _aq = _ay
                    _ap = _an[:]
            else:
                _an[_2], _an[_ae] = (_an.__getitem__(_ae), _an.__getitem__(_2))
        if any([89 > 0]):
            None
        _az = [self.cities.__getitem__(_2) for _2 in _ap]
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None
        return (_az, _aq)
        if (lambda _: (_ * _ + _) % 2 == 0)(6693):
            None

def _t():
    print((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['6\x14\x1f\x14\x03\x10\x05\x18\x1f\x16Q\x03\x10\x1f\x15\x1e', 'R\x1f', '4>#>2$', 'ÞÞÞ'], [113, 63, 87, 240]))
    _6 = _e(30, x_range=(0, 100), y_range=(0, 100), seed=42)
    print((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))([';\x1c\x1c\x1c\x11yX]', 'Þ\x92ñÞÛßÐÛÜÕ\x92\x9f\x9f\x9f'], [49, 178]))
    _a0 = _r(_6, max_iter=5000, seed=123)
    _a1, _a2 = _a0.run()
    print(f'Hill Climbing best distance: {_a2:.2f}')
    print((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ÿØØØÕ¦\x9c', 'µ\xad´¹¬', 'YX\x1c}RRY]PUR[\x1c\x14YDLSRYRH', 'T\\Q\x1d^RRQTSZ\x11\x1dNJ\\M\x14\x1d\x10\x10\x10'], [245, 216, 60, 61]))
    _a3 = _f(_6, initial_temp=500, cooling_rate=0.995, min_temp=0.01, max_iter_per_temp=50, neighbor_method=(lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)), _1) ^ _2) for _ in range(len(_0)))))('Ó×ÁÐ', 40, 136), cooling_schedule=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ìñùæçìçýà', 'v', 'Ö'], [137, 23, 186]), seed=123, verbose=True)
    _a4, _a5 = _a3.run()
    _a3.plot_tour(_a4, title=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ZH)$)Lqyfglg}`he)Jffe`', '~w08', '\x173%4m'], [9, 16, 68]))
    print((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x125558Kqumtyl}|8Yv', 'ùòöûþùð·¿ûøðöåþãÿúþô·ôøøûþ', 'U\\\x17\x1bI^M^IH^\x12\x1b\x16\x16\x16'], [24, 151, 59]))
    _a6 = _f(_6, initial_temp=500, cooling_rate=0.1, min_temp=0.1, max_iter_per_temp=30, neighbor_method=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['É', "'4", 'ÓÄÅÓ'], [187, 66, 182]), cooling_schedule=(lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['îíåãðëö', '3628'], [130, 91]), seed=123, verbose=True)
    _a7, _a8 = _a6.run()
    _a6.plot_tour(_a7, title=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ÝÏ', 'ëæë\x87¤¬ª¹¢¿£¦¢¨ë\x88', 'ÁÁÂÇÀÉ\x8e\x86üËØËÜÝË\x87'], [142, 203, 174]))
    print((lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['2\x15\x15\x15\x18kQUMTYL]\\\x18yVV]YTQV', '\xa0çï«®©¢¦µç¤¨¨«®©\xa0ëçª®¿¢£îçêêê'], [56, 199]))
    _a9 = _f(_6, initial_temp=500, cooling_rate=0.5, min_temp=0.1, max_iter_per_temp=40, neighbor_method=(lambda _0, _1, _2: ''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_0.__getitem__(_)).__xor__(_1), _2)) for _ in range(len(_0)))))(')-<! ', 37, 97), cooling_schedule=(lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['Å', 'à', '\x9d\x96\x92\x81'], [169, 137, 243]), seed=123, verbose=True)
    _ba, _bb = _a9.run()
    _a9.plot_tour(_ba, title=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['»©ÈÅÈ¤\x81\x86\x8d', '\\O\x1d~R', 'æåàçî©¡Äàñìí\xa0'], [232, 61, 137]))
    print((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['7\x00\x00', 'Ð', '4', 'Jlttxk`9$$$'], [61, 237, 20, 25]))
    print(f'Hill Climbing:      {_a2:.2f}')
    print(f'SA Exponential/Swap: {_a5:.2f}')
    print(f'SA Logarithmic/Rev:  {_a8:.2f}')
    print(f'SA Linear/Mixed:     {_bb:.2f}')
    plt.figure(figsize=(10, 5))
    plt.plot(_a3.energy_history, label=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['ñã\x82çÚÒÍÌ', 'ÅÎÔÉÁÌ', 'l\x104"3'], [162, 160, 67]))
    plt.plot(_a6.energy_history, label=(lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x02\x10q\x1d>60#', '^C_', 'Û', 'BH\x04yN]'], [81, 55, 182, 43]))
    plt.plot(_a9.energy_history, label=(lambda _e, _k: ''.join((''.join((chr((lambda: ord(_c) ^ _k.__getitem__(__i))()) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['qc\x02nKLG', 'ùê·', '\x01%', '\x11\x0c\r'], [34, 152, 76, 105]))
    plt.axhline(y=_a2, color=(lambda _0, _1, _2: ''.join((chr(ord(_0.__getitem__(_)) ^ _1 ^ _2) for _ in range(len(_0)))))("'2!9", 44, 108), linestyle='--', label=(lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))([' ', 'µ°°ü\x9f°µ±¾µ²', 'ª'], [104, 220, 205]))
    plt.xlabel((lambda _e, _k: ''.join((''.join((chr((lambda: ord(_c) ^ _k.__getitem__(__i))()) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['Øéáüéþíøù', 'CT\x11BETA'], [140, 49]))
    plt.ylabel((lambda _e, _k: ''.join((''.join((chr(ord(_c) ^ _k.__getitem__(__i)) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['êÍÛÜ\x88ÌÁÛ', '\x88\x9d', 'á', '\x7fy'], [168, 252, 143, 28]))
    plt.title((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['º\x91\x9a\x8d\x98\x86ß·\x96\x8c\x8b', '\x0f\x12\x19@#\x0f\r\x10\x01\x12\t\x13\x0f\x0e'], [255, 96]))
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def _u():
    print((lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x8e©©©¤', 'zD', '\x89\x84\x84È¼»¸È¼\x8d\x9b\x9cÈÀ½\x86\x81\x9cÈ', 'Mok\x7fl{7>333'], [132, 41, 232, 30]))
    _6 = [_b(0, 0, 'A'), _b(1, 0, 'B'), _b(1, 1, 'C'), _b(0, 1, 'D')]
    _bc = _f(_6, initial_temp=10, cooling_rate=0.9, min_temp=0.001, max_iter_per_temp=20, neighbor_method=(lambda _0, _1, _2: ''.join((chr((lambda: (lambda: ord(_0.__getitem__(_)) ^ _1)() ^ _2)()) for _ in range(len(_0)))))('WSET', 86, 114), cooling_schedule=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['\x13\x0e', 'ªµ', '383)', ']UX'], [118, 218, 93, 52]), seed=42, verbose=False)
    _az, _bd = _bc.run()
    print(f'Optimal distance should be 4.0, found: {_bd:.4f}')
    print((lambda _0, _1, _2: ''.join((chr(ord(_0.__getitem__(_)).__xor__(_1) ^ _2) for _ in range(len(_0)))))('@{af.', 132, 144), _az)
    _bc.plot_tour(_az, title=(lambda _e, _k: ''.join((''.join((chr(ord(_c).__xor__(_k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['yGK', '\x9c\x9cÐ', '\xadª©Ù\xad\x9c', 'WP'], [42, 240, 249, 36]))
if __name__.__eq__((lambda _e, _k: ''.join((''.join((chr((lambda _0, _1: _0 ^ _1)(ord(_c), _k.__getitem__(__i))) for _c in _e.__getitem__(__i))) for __i in range(len(_e)))))(['À', 'Úèä', '¶±\x80\x80'], [159, 133, 223])):
    _t()
    _u()