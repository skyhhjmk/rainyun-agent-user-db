package com.rainyun.agent.service;

public class CustomerEligibilityException extends RuntimeException {
    public enum Requirement { REAL_NAME, WECHAT }
    private final Requirement requirement;

    public CustomerEligibilityException(Requirement requirement) {
        super(requirement == Requirement.REAL_NAME ? "Rainyun real-name verification is required" : "Rainyun WeChat binding is required");
        this.requirement = requirement;
    }

    public Requirement requirement() { return requirement; }
}
