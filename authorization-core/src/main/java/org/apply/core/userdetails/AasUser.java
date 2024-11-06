package org.apply.core.userdetails;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

/**
 * @author shenqicheng
 */
@Data
public class AasUser implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 用户ID
     */
    private String userId;

    /**
     * 创建时间(用户所在系统时间)
     */
    private String createdAt;

    /**
     * 更新时间(用户所在系统时间)
     */
    private String updatedAt;


    /**
     * 用户名，用户池内唯一，区分大小写
     */
    private String username;

    /**
     * 密码
     */
    private String password;

    /**
     * 用户昵称，该字段不具备唯一性
     */
    private String nickname;

    /**
     * 图片
     */
    private String picture;

    /**
     * 邮箱，用户池内唯一，不区分大小写，如 Bob@example.com 和 bob@example.com 会识别为同一个邮箱。
     */
    private String email;

    /**
     * 邮箱是否已验证，Authing 默认不会阻止邮箱未验证的用户登录，如果你希望强制要求用户邮箱验证之后才能登录
     */
    private Boolean emailVerified;

    /**
     * 手机号，用户池内唯一
     */
    private String phone;

    /**
     * 手机号是否已验证，使用手机号验证码注册、登录的用户该字段为 true，管理员手动创建的用户此字段为 false
     */
    private Boolean phoneVerified;

    /**
     * 性别, M（Man） 表示男性、F（Female） 表示女性、 U（Unknown）表示未知
     */
    private String gender;

    /**
     * 地址，固定格式
     */
    private String address;

    /**
     * 生日
     */
    private String birthdate;

    /**
     * 时区
     */
    private String zoneInfo;

    /**
     * 语言
     */
    private String locale;

    /**
     * 用户状态
     */
    private Integer status;

    /**
     * 是否删除
     */
    private Boolean deleted = false;

    /**
     * 用户账号是否被锁定，被锁定的账号无法进行登录
     */
    private Boolean blocked = false;

    /**
     * 用户来源
     */
    private String source;

    /**
     * 租户ID集合
     */
    private Set<String> tenantIds;

    /**
     * 权限
     */
    private List<GrantedAuthority> authorities = new ArrayList<>();

    @Override
    public boolean isEnabled() {
        return !this.deleted;
    }
}
