@php
    $currentRouteName = Route::currentRouteName();
@endphp
<nav class="navbar navbar-expand-md navbar-dark bg-primary">
    <div class="container">
        <a href="{{ route('home') }}" class="navbar-brand mb-0 h1"><i class="bi-hexagon-fill me-2"></i> Data Master</a>
        <button type="button" class="navbar-toggler" data-bstoggle="collapse" data-bs-target="#navbarSupportedContent">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarSupportedContent">
            <hr class="d-md-none text-white-50">
            <ul class="navbar-nav flex-row flex-wrap">
                <li class="nav-item col-2 col-md-auto"><a href="{{ route('home') }}"
                        class="nav-link @if ($currentRouteName == 'home') active @endif">Home</a></li>
                <li class="nav-item col-2 col-md-auto"><a href="{{ route('employees.index') }}"
                        class="nav-link
@if ($currentRouteName == 'employees.index') active @endif">Employee</a></li>
            </ul>
            <hr class="d-md-none text-white-50">
            {{-- Create logout dropdown, if user logged in --}}
            @auth
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item dropdown">
                        <a href="#" class="nav-link dropdown-toggle" data-bs-toggle="dropdown">
                            <i class="bi-person me-2"></i>{{ auth()->user()->name }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a href="{{ route('logout') }}" class="dropdown-item"
                                    onclick="event.preventDefault(); document.getElementById('logout-form').submit();">
                                    <i class="bi-box-arrow-right me-2"></i>Logout</a>
                            </li>
                        </ul>
                    </li>
                </ul>
                <form id="logout-form" action="{{ route('logout') }}" method="POST" class="d-none">
                    @csrf
                </form>
            @endauth
        </div>
    </div>
</nav>
